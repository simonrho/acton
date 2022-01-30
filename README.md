# Acton


`acton` provides a `linux` API for ethernet over udp networking using Rust.

## Examples

More examples, including a packet logger, and a version of the ethernet over udp server & client
written, can be found in the `examples/` directory.

### Ethernet over udp server & client

This code implements an Ethernet over udp server and client. Whenever a
ethernet frame @ server is received on an interface, it sends the packet to clients, and Vice versa.
In service, simple ethernet mac learning is implemented with mac forwarding table aging.
The BUM (Broadcast, Unknown, Multicast) frame sent by server will be flooded to all clients.
But local switch between clients is not allowed (P2MP forwarding manner).
Proprietary control packets are defined and used for a session lifecycle management (hello and keepalive control packets)

### Scaling

1,000 clients are tested (linux system resource limitation should be considered)

### Install
tbd
