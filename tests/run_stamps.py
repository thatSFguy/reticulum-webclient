#!/usr/bin/env python3
"""
Stamp conformance runner. Spawns tests/stamps.mjs (which runs its own
Node-side self-checks first), then validates every vector it prints
against RNS's reference implementation (RNS >= 1.6, RNS.Stamps):

  - fractional cost targets      RNS.Stamps.target_from_cost
  - stamp values (float/legacy)  RNS.Stamps.stamp_value / stamp_value_legacy
  - LXMF workblock expansion     RNS.Stamps.stamp_workblock
  - generated LXMF stamps        RNS.Stamps.stamp_valid over the workblock
  - stamped link-request key     stamp_valid(pub, cost, material) + X25519
  - path-request stamp           RNS.Transport.validate_pr_stamp
  - stamped announce             RNS.Identity.validate_announce strips the
                                 trailer and recalls lr_cost (SPEC §4.7)

Exit 0 on all-pass, 1 otherwise. Called from CI (.github/workflows/verify.yml).
"""
import json
import os
import subprocess
import sys
import tempfile

import RNS
from RNS import Identity, Packet
from RNS import Stamps
from RNS.Cryptography import X25519PrivateKey
import LXMF
from LXMF import LXStamper
import hashlib

OK = "\033[32mOK\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36m..\033[0m"

results = []


def check(cond, label, detail=""):
    results.append(bool(cond))
    print(f"   {OK if cond else FAIL} {label}{'' if cond or not detail else ' — ' + detail}")


def run_harness():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run(["node", "tests/stamps.mjs"], cwd=root, capture_output=True, text=True)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print(f"{FAIL} tests/stamps.mjs exited {r.returncode}")
        sys.exit(1)
    return json.loads(r.stdout)


def main():
    print(f"{INFO} RNS {RNS.__version__ if hasattr(RNS, '__version__') else '?'}")
    cfg = tempfile.mkdtemp(prefix="rlw-stamps-")
    RNS.Reticulum(configdir=cfg, loglevel=0)

    print(f"{INFO} running tests/stamps.mjs ...")
    v = run_harness()

    print(f"{INFO} cost targets")
    for t in v["targets"]:
        want = Stamps.target_from_cost(t["cost"])
        check(int(t["target"], 16) == want, f"target({t['cost']})", f"js={t['target']} rns={want:x}")

    print(f"{INFO} stamp values")
    bad = 0
    for s in v["values"]:
        wb, st = bytes.fromhex(s["wb"]), bytes.fromhex(s["stamp"])
        if Stamps.stamp_value(wb, st) != s["value"] or Stamps.stamp_value_legacy(wb, st) != s["legacy"]:
            bad += 1
            print(f"      value mismatch: js={s['value']}/{s['legacy']} rns={Stamps.stamp_value(wb, st)}/{Stamps.stamp_value_legacy(wb, st)}")
    check(bad == 0, f"{len(v['values'])} stamp_value / stamp_value_legacy pairs")

    print(f"{INFO} LXMF workblocks")
    for w in v["workblocks"]:
        wb = Stamps.stamp_workblock(bytes.fromhex(w["material"]), expand_rounds=w["rounds"])
        check(hashlib.sha256(wb).hexdigest() == w["sha256"], f"stamp_workblock(rounds={w['rounds']})")

    print(f"{INFO} generated LXMF stamps")
    for s in v["lxmf"]:
        wb = Stamps.stamp_workblock(bytes.fromhex(s["messageId"]))
        st = bytes.fromhex(s["stamp"])
        check(Stamps.stamp_valid(st, s["cost"], wb), f"LXMF stamp at cost {s['cost']} accepted by RNS")
        check(Stamps.stamp_value(wb, st) == s["value"], f"LXMF stamp value {s['value']} agrees")

    print(f"{INFO} stamped LXMF message (LXMF {getattr(LXMF, '__version__', '?')})")
    lm = v["lxmfMessage"]
    RNS.Identity.remember(os.urandom(32), bytes.fromhex(lm["source"]), bytes.fromhex(lm["publicKey"]))
    m = LXMF.LXMessage.unpack_from_bytes(bytes.fromhex(lm["pow"]["bytes"]))
    check(m.message_id.hex() == lm["messageId"], "LXMF message_id matches the JS sender's", f"lxmf={m.message_id.hex()}")
    check(m.signature_validated, "LXMF validates the signature of the stamped message")
    check(m.stamp is not None and m.stamp.hex() == lm["pow"]["stamp"], "LXMF extracts the 32-byte stamp")
    check(m.validate_stamp(lm["cost"]), f"LXMessage.validate_stamp({lm['cost']}) accepts the PoW stamp")
    check(LXStamper.stamp_valid(m.stamp, lm["cost"], LXStamper.stamp_workblock(m.message_id)),
          "stamp valid over the EXPANDED workblock (what LXMF <= 1.2 requires)")
    t = LXMF.LXMessage.unpack_from_bytes(bytes.fromhex(lm["ticket"]["bytes"]))
    check(t.signature_validated and t.message_id.hex() == lm["messageId"], "ticket-stamped message: id + signature")
    check(t.validate_stamp(99, tickets=[bytes.fromhex(lm["ticket"]["ticket"])]) and t.stamp_value == LXMF.LXMessage.COST_TICKET,
          "LXMessage.validate_stamp accepts the 16-byte ticket stamp")

    print(f"{INFO} stamped link-request key")
    k = v["keystamp"]
    priv, pub, mat = bytes.fromhex(k["priv"]), bytes.fromhex(k["pub"]), bytes.fromhex(k["material"])
    check(X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes() == pub, "X25519 priv -> pub matches")
    check(Stamps.stamp_valid(pub, k["cost"], mat), f"key stamp valid at cost {k['cost']}")

    print(f"{INFO} stamped LINKREQUEST (value {v['linkrequest']['value']}, {v['linkrequest']['ms']} ms)")
    lr = v["linkrequest"]
    lp = Packet(None, None)
    lp.raw = bytes.fromhex(lr["packet"])
    lp.unpack()
    xpub, edpub = lp.data[:32], lp.data[32:64]
    check(lp.packet_type == RNS.Packet.LINKREQUEST and len(lp.data) == 67, "LINKREQUEST shape (67 bytes, signalling kept)")
    check(Stamps.stamp_valid(xpub, lr["cost"], bytes.fromhex(lr["dest"]) + edpub),
          f"RNS accepts the stamped key at lr_cost {lr['cost']} (material dest||ed25519_pub)")
    check(X25519PrivateKey.from_private_bytes(bytes.fromhex(lr["priv"])).public_key().public_bytes() == xpub,
          "link X25519 private key matches the stamped public key")

    print(f"{INFO} path request")
    p = v["prstamp"]
    pp = Packet(None, None)
    pp.raw = bytes.fromhex(p["packet"])
    pp.unpack()
    check(pp.destination_hash.hex() == "6b9f66014d9853faab220fba47d02761" and len(pp.data) == 64, "path? packet: PLAIN dest, 64-byte payload")
    parsed = RNS.Transport.parse_path_request(pp.data)
    check(parsed is not None and parsed[0].hex() == p["dest"] and parsed[1].hex() == p["transportId"] and parsed[2].hex() == p["tag"],
          "RNS.Transport.parse_path_request splits dest / transport_id / tag", repr(parsed))
    check(RNS.Transport.validate_pr_stamp(bytes.fromhex(p["stamp"]), bytes.fromhex(p["dest"]), bytes.fromhex(p["tag"])),
          "RNS.Transport.validate_pr_stamp accepts it at PR_COST")

    print(f"{INFO} stamped announce (value {v['announce']['value']}, {v['announce']['rounds']} rounds, {v['announce']['ms']} ms)")
    a = v["announce"]
    pkt = Packet(None, None)
    pkt.raw = bytes.fromhex(a["packet"])
    pkt.unpack()
    dest = bytes.fromhex(a["destHash"])
    check(Identity.validate_announce(pkt) is True, "RNS.Identity.validate_announce accepts the stamped announce")
    check(Identity.recall_app_data(dest) == bytes.fromhex(a["appData"]), "trailer stripped (stamp validated upstream)")
    check(Identity.recall_link_cost(dest) == a["lrCost"], f"recall_link_cost == {a['lrCost']}")

    passed = sum(results)
    print()
    if passed == len(results):
        print(f"{OK} all {len(results)} stamp checks passed")
        sys.exit(0)
    print(f"{FAIL} {passed}/{len(results)} stamp checks passed")
    sys.exit(1)


if __name__ == "__main__":
    main()
