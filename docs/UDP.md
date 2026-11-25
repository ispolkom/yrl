# YRL over UDP (2026-10-08)

A session can use a reliable stream over UDP (`crates/yrl/src/udp.rs`) instead of TCP. Everything above it — Noise, login, resumable `Link`, commands, and files — is unchanged: the layer above sees an ordinary `AsyncRead + AsyncWrite` stream.

## Stream design

- Packet: a 35-byte header (kind, 64-bit connection number, packet number, acknowledgement, receiver window, and a 64-packet selective-ack bitmap), followed by up to 1,100 data bytes.
- Loss recovery: retransmission timer shared by the connection (grows on consecutive timeouts and resets on any progress), plus fast retransmission after three later packets have arrived.
- Throughput: the send window grows on success and shrinks on loss; the 512-packet receive window bounds memory use.
- Shutdown: a connection closes only after all data is acknowledged. Forty seconds without progress marks it dead, after which the `Link` layer resumes the session.

## Security

- Headers are unauthenticated and carry no secrets. Forging one can only disrupt the connection, as with any UDP flow; Noise protects the enclosed data and rejects tampering. Invalid headers are silently ignored rather than resetting a connection, because otherwise a stranger could reset someone else's connection.
- The connection number is 64 random bits. A packet from a foreign address using an existing number is ignored.
- The server remains silent: it sends nothing, not even acknowledgements, until the layer above writes its first byte, which happens only after a valid handshake. Foreign packets receive no response, so there is no reflection amplification.
- Only a packet with connection number zero and data can open a new connection, and only from an address admitted by the gate (in production, one that knocked), while a `conn_slots` slot is free and the address has fewer than `MAX_UDP_PER_IP` (8) connections. An incomplete handshake disappears after the handshake timeout.
- The same set of addresses admitted by knocking closes data ports for UDP (`udp dport`). An established stream outlives the opening window (`ct state established`). This is verified against a real kernel in a private network (`tests/nft_real.rs`).

## Enabling it

- Server (gatekeeper): `--udp addr:port`, using the same port number as TCP.
- Client: `--udp host:port`, together with `--knock` when the gate is enabled.

## Tests

`tests/udp.rs` covers the stream over a clean channel and under 10%/30% loss with reordering and duplication, plus silence. `tests/udp_session.rs` covers the full stack: a 6 MiB file in both directions, a session under 5% loss, no response bytes to a stranger, many connection numbers from one address, and forged headers against a live connection. `tests/spa.rs` and `tests/nft_real.rs` cover gate rules.

## Not implemented

NAT traversal (hole punching), UDP relay, migration to another address without a fresh handshake (a new connection currently resumes through `Link`), fallback to TCP when UDP receives no response, send pacing (the window can release bursts), and path-MTU discovery.

## Known limitation

The UDP header is not authenticated. An on-path attacker who knows the 64-bit connection number can send an acknowledgement beyond the highest packet sent. The receiver rejects that packet, but legitimate packets in that direction are also rejected until the connection dies after 40 seconds without progress and the session layer resumes it. Noise would detect modified data and close the session immediately. Resetting on an invalid unauthenticated header would let outsiders reset other users' connections, so that behavior is intentionally omitted.
