Implement a udp forwarder that exposes one UDP server port of a client on a server:
the server listens and forwards to the client, which sits behind NAT.

# Protocol design

The server and client configs share a pre-shared key; the KDF result of that key is the
HMAC key.

The server listens on 2 UDP ports.

The first port is the control port. The client sends 0x00, the current timestamp, and the
HMAC of that timestamp. On receipt the server verifies the HMAC and the timestamp (must be
within 1 minute) and takes that UDP port as the port it talks to the client on, then
replies with a 0x02 ACK (echoed client timestamp + server timestamp + HMAC). The client
sends a handshake every 30 seconds as a heartbeat, which refreshes the NAT mapping and
confirms the link is alive.

The second port is the data port. Clients on the internet send packets to this port as
usual. The server prefixes the payload with a 48-bit IPv4 address + port header and sends
it to the client's communication port. The client emulates the different clients with
127.0.0.1 sockets, talks to the local udp service, then takes the replies of the udp
server, prefixes them with 0x01 and the 48-bit IPv4 address + port header, and sends them
to the server control port; the server forwards them back through the data port to the
internet client.

The first byte of every message on the control port is a type, so data messages from the
server to the client also carry a 0x01 prefix (0x01 + 48-bit header + payload) so that they
can be told apart from the 0x02 ACK.

The client keeps a mapping from 127.0.0.1 port to ipv4+port. Ports idle for 2 minutes must
have their mapping removed.

IPv4 only.

# Requirements

Plain C.
Networking with epoll only.
Crypto library: libsodium only.
Config files in ini.
Static linking, musl as libc.
libsodium built from source into a static library.
