# FAQProxy

[![Build](https://github.com/timbergeron/faqproxy/actions/workflows/build.yml/badge.svg)](https://github.com/timbergeron/faqproxy/actions/workflows/build.yml)

FAQProxy is a clean, NetQuake-only recreation of the original FAQProxy idea: put a protocol-aware process between a Quake client and server so routing, recording, inspection, and later extensions can live outside either engine.

This repository is an independent implementation. It is not the historical FAQProxy source and is not affiliated with its original authors.

## Historical credit

The original FAQProxy was created in 1997 by Juha “Perkele” Kujala and Ilkka “Zibbo” Rajala of the Finnish Allied Quakers (FAQ) clan. Their protocol-aware NetQuake proxy pioneered external demo recording, spectator and chase-camera experiments, teamplay tools, and programmable network routing without requiring changes to the client or server. Their work later evolved into Qizmo and helped establish the idea of a game-aware proxy as an extension platform.

This project is named in recognition of that work. All credit for the original FAQProxy concept, design, and historical implementation belongs to Perkele, Zibbo, and the original FAQProxy contributors. The code in this repository is a new implementation based on publicly understood NetQuake protocol behavior and modern engine references.

## What works now

- NetQuake UDP connection and control protocol version 3
- Game protocols 15 (NetQuake), 666 (FitzQuake), and 999 (RMQ)
- NetQuake's reliable, fragmented, acknowledged stream and unreliable datagrams
- ProQuake handshake extensions and 16-bit client-angle negotiation
- Multiple simultaneous clients, each with an isolated upstream UDP socket
- Server-browser, player-info, rule-info, and RCON control-packet forwarding to one fixed server
- Protocol detection from reassembled `svc_serverinfo` messages, including FTE extension preambles
- First-person NetQuake `.dem` recording with protocol-aware view-angle extraction
- Native Windows, Linux, and macOS builds with no third-party runtime libraries

There is deliberately no QuakeWorld code here. FAQProxy does not translate QW into NQ, and it does not turn a protocol-15 client into a protocol-666/999 client. The client and server still speak the same native game protocol; the proxy preserves their packets byte for byte.

## How it is arranged

```text
JoeQuake / Quakespasm / QSS-M
             |
             | NetQuake UDP 15, 666, or 999
             v
         FAQProxy VPS
             |
             | same native NetQuake packets
             v
       NetQuake game server
```

FAQProxy terminates the connectionless NetQuake handshake just far enough to replace the server's accepted UDP port with its own public port. After that, connected packets are relayed unchanged. This is important: the original sequence numbers and acknowledgements stay end to end, while 666/999 entity, coordinate, and angle encodings remain untouched.

At the same time, a read-only inspector reassembles reliable server messages. It identifies 15/666/999 and feeds complete messages into the demo writer without delaying packet forwarding.

## Build and test

You need a C11 compiler, Make, and Python 3 for the black-box test only.

```sh
make
make test
```

The binary is `build/faqproxy`. The tests start a mock NetQuake server and client and exercise redirected game ports, reliable fragment acknowledgements, unreliable traffic, reconnects, ProQuake negotiation, FTE2 prediction framing, and demo view angles across protocols 15, 666, and 999.

GitHub Actions runs the same build and tests on Windows, Linux, and macOS for every push to `main` and every pull request. Successful runs retain downloadable `faqproxy-windows-x86_64`, `faqproxy-linux`, and `faqproxy-macos` binaries for 14 days. The Linux job also runs the sanitizer test target.

On Windows, use an MSYS2 UCRT64 shell with its GCC, Make, and Python packages, then run the same `make test` command. The resulting native executable is `build/faqproxy.exe`; Winsock is its only networking dependency. You can also download the Windows artifact from a successful GitHub Actions run without installing a compiler.

For an AddressSanitizer and UndefinedBehaviorSanitizer build:

```sh
make sanitize
```

Install under `/usr/local/bin`, or override `PREFIX` and `DESTDIR` for packaging:

```sh
sudo make install
```

## Run it locally

Forward local UDP port 26000 to a NetQuake server:

```sh
./build/faqproxy quake.example.net:26000
```

Record each connection as a demo:

```sh
./build/faqproxy --record-dir demos quake.example.net:26000
```

Then connect the client to the proxy, not the real server:

```text
connect 127.0.0.1:26000
```

Use `-v` for additional diagnostics and `-vv` for one line per forwarded datagram. Run `./build/faqproxy --help` for all options.

## Run it on a VPS

On the VPS, build or copy the binary and select one fixed upstream NetQuake server:

```sh
./faqproxy \
  --listen 0.0.0.0:26000 \
  --record-dir ./demos \
  quake.example.net:26000
```

Allow inbound UDP port 26000 in both the VPS provider firewall and the host firewall. Clients then use:

```text
connect your.vps.address:26000
```

Only the configured upstream server can be reached through the process, so this is not an open UDP relay. It does not provide authentication, encryption, or source-address validation, however. NetQuake predates modern challenge handshakes: anyone who can reach the listen port can attempt to occupy a server slot, reflect replies toward a spoofed UDP source, or use an RCON endpoint exposed by the upstream server. Use a host/provider firewall to restrict the source networks when the proxy is not intended to be public, keep `--max-clients` bounded, and use a strong upstream RCON password.

[`docs/faqproxy.service`](docs/faqproxy.service) is a hardened systemd starting point. It expects the binary installed at `/usr/local/bin/faqproxy` and a dedicated `faqproxy` system user. Replace the upstream hostname and port, then validate the unit with `systemd-analyze verify` before enabling it.

## Demo recording notes

Recorded files use the standard NetQuake demo layout and retain the server's native 15, 666, or 999 messages. QSS-M, Quakespasm-family clients, and JoeQuake builds that support the recorded protocol can play them.

The recorder follows the connected player's point of view. It reads client movement angles as 8-bit protocol-15 angles, negotiated ProQuake angles, FTE2 prediction angles, 16-bit protocol-666 angles, or the angle mode selected by protocol-999 flags. Demo files are created exclusively and an existing path is never overwritten. Unix builds use mode `0640`; Windows files inherit the recording directory's access-control list. Packet forwarding does not depend on recording, so a recording error stops that demo but leaves the game connected.

## Current boundaries

- IPv4 only in version 0.1; IPv6 is a planned transport extension.
- One configured upstream server per process. Run another instance/port for another server.
- No compression, artificial latency/loss, chasecam, team macros, menus, or TCP tunneling yet.
- The inspector recognizes only protocols 15, 666, and 999. Relay traffic is never rewritten to fake compatibility with an unsupported client.
- FAQProxy is a user-space relay, so the route adds the client-to-VPS and VPS-to-server network legs.
- NetQuake has no cryptographic connection challenge; firewall policy remains the primary protection for a private deployment.

The next sensible historical features are capture metadata and demo controls, followed by an optional spectator/chasecam state layer. Network simulation and tunneling can remain separate modules so the native relay stays auditable.

## Source references

The wire definitions were checked against the local QSS-M and JoeQuake sources, including their `protocol.h`, `net_defs.h`, `net_dgrm.c`, `cl_parse.c`, `cl_input.c`, and `cl_demo.c` implementations. FAQProxy's code is newly written and intentionally small; it does not link to either engine.

## License

MIT. See [LICENSE](LICENSE).
