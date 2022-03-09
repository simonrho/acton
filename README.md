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

### How to Install
```shell
wget https://github.com/simonrho/acton/raw/main/target/release/examples/acton; chmod +x ./acton
```

### How to Use

```shell
root@r1:~/acton# ./acton
acton 0.1.0
Ethernet over UDP tunnel tools

USAGE:
    acton <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    client    client connect mode for L2 tunnel establishment
    help      Prints this message or the help of the given subcommand(s)
    server    server listen mode for L2 tunnel requests
```
#### Running server
```shell
root@r1:~/acton# ./acton server --help
acton-server 0.1.0
server listen mode for L2 tunnel requests

USAGE:
    acton server [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --address <address>      tap ip network (a.b.c.d/n) [env: CLIENT_TAP_NETWORK=]  [default: 0.0.0.0/0]
    -l, --listen <listen>        server listen address [env: SERVER_LISTEN_ADDRESS=]  [default: 0.0.0.0]
    -m, --mac <mac>              tap mac address (xx:xx:xx:xx:xx:xx) [env: SERVER_TAP_MAC=]  [default:
                                 00:00:00:00:00:00]
    -p, --port <port>            server listen port [env: SERVER_LISTEN_PORT=]  [default: 8080]
    -t, --tap-name <tap-name>    tap interface name [env: SERVER_TAP_NAME=]  [default: server]
root@r1:~/acton#
root@r1:~/acton# target/release/examples/acton server -m 00:01:02:03:04:05 -a 100.0.0.1/24
[2022-01-30T10:35:24Z INFO  acton::server] server starts!

```

#### Running client
```shell
root@r2:~/acton# ./target/release/examples/acton client -h
acton-client 0.1.0
client connect mode for L2 tunnel establishment

USAGE:
    acton client [OPTIONS] <server>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --address <address>      tap ip network (a.b.c.d/n) [env: CLIENT_TAP_NETWORK=]  [default: 0.0.0.0/0]
    -m, --mac <mac>              tap mac address (xx:xx:xx:xx:xx:xx) [env: CLIENT_TAP_MAC=]  [default:
                                 00:00:00:00:00:00]
    -p, --port <port>            server destination port [env: CLIENT_SERVER_PORT=]  [default: 8080]
    -t, --tap-name <tap-name>    tap interface name [env: CLIENT_TAP_NAME=]  [default: client]

ARGS:
    <server>    server destination address [env: CLIENT_SERVER_ADDRESS=]

Beware `-d`, interoperable with socat command
root@r2:~/acton# ./target/release/examples/acton client 192.168.99.11 -a 100.0.0.2/24 -t client -m 00:02:03:04:05:06
[2022-01-30T10:38:10Z INFO  acton::client] client starts
[2022-01-30T10:38:10Z INFO  acton::client] connected: 192.168.99.11:8080
```

#### ping test
```shell
root@r2:~/acton# ping 100.0.0.1
PING 100.0.0.1 (100.0.0.1) 56(84) bytes of data.
64 bytes from 100.0.0.1: icmp_seq=1 ttl=64 time=0.971 ms
64 bytes from 100.0.0.1: icmp_seq=2 ttl=64 time=0.990 ms
64 bytes from 100.0.0.1: icmp_seq=3 ttl=64 time=1.05 ms
64 bytes from 100.0.0.1: icmp_seq=4 ttl=64 time=1.22 ms
64 bytes from 100.0.0.1: icmp_seq=5 ttl=64 time=0.875 ms
64 bytes from 100.0.0.1: icmp_seq=6 ttl=64 time=1.05 ms
^C
--- 100.0.0.1 ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5064ms
rtt min/avg/max/mdev = 0.875/1.027/1.222/0.105 ms
root@r2:~/acton#
```