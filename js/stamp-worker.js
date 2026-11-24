// js/stamp-worker.js — Web Worker body for proof-of-work stamp search.
//
// Spawned (several at once) by js/stamps.js runInWorkers(). Receives one
// job { kind: 'hash'|'key', prefix, size, T } and searches until it finds
// a hit, posting periodic progress. The page terminates every worker as
// soon as one reports 'found' or the job times out, so there is no
// cancel message. Relative imports only: workers don't see import maps.

import { makeSearcher, searchHash, searchKey } from './stamps.js';

self.onmessage = (ev) => {
  const job = ev.data;
  const searcher = makeSearcher(new Uint8Array(job.prefix), job.size);
  const chunk = job.kind === 'key' ? 4096 : 200000;
  let total = 0;
  for (;;) {
    const res = job.kind === 'key'
      ? searchKey(searcher, job.T, chunk)
      : searchHash(searcher, job.T, chunk);
    total += res.rounds;
    if (res.stamp || res.priv) {
      self.postMessage({ type: 'found', stamp: res.stamp, priv: res.priv, pub: res.pub, rounds: total });
      return;
    }
    self.postMessage({ type: 'progress', rounds: total });
  }
};
