# Security and trust model

All Reticulum protocol work — identity generation, ECDH key exchange, AES-256-CBC encryption, HMAC authentication, Ed25519 signing, LXMF message packing — runs inside your browser (or the Android WebView). The radio or daemon on the other end of the transport only sees fully encrypted packets.

## What is protected

- **Message content** is end-to-end encrypted. Each LXMF message uses a fresh ephemeral X25519 key exchange, HKDF-SHA256 key derivation, and AES-256-CBC + HMAC-SHA256 (Reticulum's Token / modified Fernet construction). Neither the transport layer, relay nodes, nor the rnsd daemon can read your messages.
- **Delivery receipts** on link-delivered messages include an Ed25519 signature that is computationally unforgeable without the responder's private key.
- **Announce signatures** are Ed25519-signed over the full announce body including the destination hash, public key, name hash, random hash, ratchet (if present), and app data. Forging an announce for a destination you do not own the private key for is infeasible.

## What is NOT protected (known limitations)

- **Private keys at rest** are stored unencrypted in the browser's IndexedDB. Anyone with access to your browser profile — browser extensions with matching host permissions, device backup tools, physical access to an unlocked device, or root access on Android — can extract them. The Export Identity file is likewise unencrypted JSON containing the complete signing and encryption private keys. Treat it like a password.
- **Forward secrecy is partial.** The ratchet keypair rotates on every announce (~5 min) and the new public key is advertised; retired ratchet private keys are not persisted, so traffic a peer encrypted to an expired ratchet can't be recovered from the stored identity. Caveats: peers that don't yet know a ratchet fall back to your long-term X25519 key (no FS for that traffic), and the current ratchet plus long-term key still live unencrypted in IndexedDB — anyone who extracts those can read messages encrypted to them.
- **BLE transport is cleartext at L2.** Web Bluetooth does not request BLE bonding, so the NUS link between your device and the RNode modem is not encrypted at the Bluetooth radio layer. An observer within Bluetooth range (~10 m) can see the encrypted Reticulum packets and their headers (destination hashes, packet types, sizes, timing) but cannot decrypt message content.
- **WebSocket `ws://` to remote hosts exposes packet headers.** When using the WebSocket transport to a non-localhost destination over `ws://` (not `wss://`), Reticulum packet headers are visible to network observers on the path. Message content remains end-to-end encrypted, but destination hashes, packet types, and timing metadata leak. The app shows a visible warning banner when a non-localhost `ws://` connection is active. Use `wss://` for remote connections if your bridge supports TLS.
- **Metadata.** Reticulum packet headers contain 16-byte destination hashes in cleartext by design. Any observer on the radio channel or transport path can correlate who is communicating with whom by watching destination hashes, even though they cannot read message content. Periodic announces broadcast your full 64-byte public key, display name, and destination hash to the mesh every five minutes. This is inherent to the Reticulum protocol, not specific to this client.
- **Map tiles.** The Nodes view loads map tiles from OpenStreetMap (`tile.openstreetmap.org`). The tile server sees your IP address and the geographic region you are viewing, though it does not see your Reticulum identity or messages.

## Recommendations

1. Do not run this on a device where untrusted browser extensions have access to your browsing data.
2. Use `wss://` (not `ws://`) for any WebSocket connection to a remote host.
3. Keep your Export Identity JSON file in a secure location (password manager, encrypted drive). Anyone who obtains it can impersonate you and decrypt your messages.
4. Understand that your display name and destination hash are broadcast to the mesh every five minutes. Do not use a display name that reveals information you want to keep private.
