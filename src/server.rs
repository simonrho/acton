use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::time;

use std::net::Ipv4Addr;
use std::process::exit;
use std::str::FromStr;
use std::time::{Duration};

use eui48::MacAddress;
use ipaddress::IPAddress;
use nom::HexDisplay;

use crate::control;
use crate::control::{KEEPALIVE_TIMEOUT, MAX_MAC_AGING_TIMEOUT, ForwardingTable, Error};
use crate::linuxtap::LinuxTapInterface;

/// Run ethernet p2mp tunnel over ip server.
///
/// # Arguments
///
/// * `listen_addr` - server listen address:port str.
/// * `tap_name` - name of tap interface that will be created.
/// * `mac` - tap interface mac.
/// * `tap_network_address` - tap interface ip network.
/// * `ipv6_filter` - filter any ipv6 packet at tap interface input path (mainly for unit/doc test purpose)
///
/// # Example
/// ```
/// use std::net::SocketAddr;
/// use std::str::FromStr;
/// use std::time::Duration;
///
/// use tokio::runtime::Runtime;
/// use tokio::time::sleep;
/// use tokio::net::UdpSocket;
///
/// use eui48::MacAddress;
/// use ipaddress;
///
/// use hex;
/// use nom::{AsBytes, HexDisplay};
///
/// use acton::linuxinterface::raw_interface;
/// use acton::{control, server};
/// Runtime::new().unwrap().block_on(async {
///     let tap_name = "tap-server";
/// 
///     // start server
///     tokio::spawn(async move {
///         server::server(
///             "127.0.0.1:8080",
///             tap_name.clone(),
///             MacAddress::from_str("00:01:02:03:04:05").unwrap(),
///             ipaddress::ipv4::new("1.2.3.1/24").unwrap(),
///             true,
///         ).await.unwrap();
///     });
/// 
///     // wait for server running...
///     sleep(Duration::from_secs(1)).await;
/// 
///     // bind raw interface for tap interface input/output validation
///     let (_interface, port_tx, mut port_rx) = raw_interface(tap_name.clone());
/// 
/// 
///     const NUM_OF_CLIENTS: usize = 100;
/// 
///     let ref mut client_sockets: Vec<UdpSocket> = Vec::new();
/// 
///     //
///     // clients -> server: session creation & unicast path check
///     //
///     println!("[Client to Server path check]");
///     let ref mut sent_packets: Vec<bytes::Bytes> = Vec::new();
/// 
///     // client session emulation
///     for i in 0..NUM_OF_CLIENTS {
///         let remote_addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
///         let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
/// 
///         let socket = UdpSocket::bind(local_addr).await.unwrap();
///         socket.connect(&remote_addr).await.unwrap();
/// 
///         /// the hello packet for client session creation on server
///         socket.send(control::HELLO_PACKET).await.unwrap();
/// 
///         client_sockets.push(socket);
///     }
/// 
///     // clients -> server: unicast packet sent
///     for i in 0..NUM_OF_CLIENTS {
///         let packet = hex::decode(format!("0001223344550001aabb{:04x}1234c0ff", i)).unwrap();
///         let packet = bytes::Bytes::from(packet);
/// 
///         client_sockets[i].send(packet.clone().as_bytes()).await.unwrap();
///         println!("CLIENT TX packet{}:\n{}", i, packet.to_hex(16));
/// 
///         sent_packets.push(packet);
///     }
/// 
///     // validate unicast packet arrival @ server
///     for i in 0..NUM_OF_CLIENTS {
///         let packet = port_rx.recv().await.unwrap();
/// 
///         assert_eq!(packet, sent_packets[i]);
/// 
///         println!("SERVER RX packet{}:\n{}", i, packet.to_hex(16));
///     }
/// 
///     //
///     // server -> clients: broadcast path check
///     //
///     println!("[Server to client broadcast path check]");
///     let broadcast_packet = hex::decode("ffffffffffff0001aaaaaaff4321c0ff").unwrap();
///     let broadcast_packet = bytes::Bytes::from(broadcast_packet);
///     let _ = port_tx.send(broadcast_packet.clone()).await;
/// 
///     println!("sent broadcast packet to clients:\n{}", broadcast_packet.to_hex(16));
/// 
///     /// check if broadcast packet arrives at each client?
///     let mut buf = [0u8; 2000];
///     for i in 0..NUM_OF_CLIENTS {
///         let n = client_sockets[i].recv(&mut buf).await.unwrap();
///         let packet = &buf[0..n];
/// 
///         assert_eq!(packet, broadcast_packet);
/// 
///         println!("CLIENT RX broadcast packet{}:\n{}", i, packet.to_hex(16));
///     }
/// 
///     //
///     // server -> clients: unknown destination mac fooding to all clients
///     //
///     println!("[Server to client broadcast path check]");
///     let unknown_mac_packet = hex::decode("000111aa22bb0001aaaaaaff4321c0ff").unwrap();
///     let broadcast_packet = bytes::Bytes::from(unknown_mac_packet);
///     let _ = port_tx.send(broadcast_packet.clone()).await;
/// 
///     println!("sent broadcast packet to clients:\n{}", broadcast_packet.to_hex(16));
/// 
///     // check if broadcast packet arrives at each client?
///     let mut buf = [0u8; 2000];
///     for i in 0..NUM_OF_CLIENTS {
///         let n = client_sockets[i].recv(&mut buf).await.unwrap();
///         let packet = &buf[0..n];
/// 
///         assert_eq!(packet, broadcast_packet);
/// 
///         println!("CLIENT RX broadcast packet{}:\n{}", i, packet.to_hex(16));
///     }
/// 
///     //
///     // server -> clients: unicast path check
///     //
///     println!("[Server to client unicast path check]");
///     let ref mut sent_packets: Vec<bytes::Bytes> = Vec::new();
/// 
///     // server -> clients: unicast packet sent
///     for i in 0..NUM_OF_CLIENTS {
///         let unicast_packet = hex::decode(format!("0001aabb{:04x}0001aaaaaaff4321c0ff", i)).unwrap();
///         let unicast_packet = bytes::Bytes::from(unicast_packet);
/// 
///         let _ = port_tx.send(unicast_packet.clone()).await;
///         println!("SERVER TX packet{}:\n{}", i, unicast_packet.to_hex(16));
/// 
///         sent_packets.push(unicast_packet);
///     }
/// 
///     // validate if unicast packet sent from server arrives @ each client
///     let mut buf = [0u8; 2000];
///     for i in 0..NUM_OF_CLIENTS {
///         let n = client_sockets[i].recv(&mut buf).await.unwrap();
///         let packet = bytes::Bytes::copy_from_slice(&buf[..n]);
/// 
///         assert_eq!(packet, sent_packets[i]);
/// 
///         println!("CLIENT RX packet{}:\n{}", i, packet.to_hex(16));
///     }
/// 
///     println!("...done...");
/// });
/// ```
pub async fn server(listen_addr: &str, tap_name: &str, mac: MacAddress, tap_network_address: IPAddress, ipv6_filter: bool) -> Result<(), Error> {
    let mut tap = match LinuxTapInterface::new(tap_name).await {
        Ok(tap) => tap,
        Err(e) => {
            error!("{:?}", e);
            exit(1);
        }
    };

    if !tap_network_address.is_unspecified() {
        let address = Ipv4Addr::from_str(tap_network_address.to_s().as_str()).unwrap().octets();
        let netmask = Ipv4Addr::from_str(tap_network_address.netmask().to_s().as_str()).unwrap().octets();
        let broadcast = Ipv4Addr::from_str(tap_network_address.broadcast().to_s().as_str()).unwrap().octets();

        if tap.set_address(&address) < 0 {
            error!("ioctl: fail to set ip address");
            exit(1);
        }
        if tap.set_netmask_address(&netmask) < 0 {
            error!("ioctl: fail to set netmask address");
            exit(1);
        }
        if tap.set_brd_address(&broadcast) < 0 {
            error!("ioctl: fail to set broadast address");
            exit(1);
        }
    }

    if !mac.is_nil() {
        let mut local_mac = [0u8; 6];
        local_mac.copy_from_slice(mac.as_bytes());

        if tap.set_mac_address(&local_mac) < 0 {
            error!("ioctl: fail to set mac address");
            exit(1);
        }
    }

    if tap.set_mtu(1500) < 0 {
        error!("ioctl: fail to set mtu size");
        exit(1);
    }

    if tap.set_up() < 0 {
        error!("ioctl: fail to set tap interface up");
        exit(1);
    }

    let (ref mut tap_tx, ref mut tap_rx) = tap.get_file();


    let socket = UdpSocket::bind(listen_addr).await?;

    info!("server starts!");


    let mut buf_tap = [0u8; control::MAX_FRAME_SIZE];
    let mut buf_sock = [0u8; control::MAX_FRAME_SIZE];

    let mut interval = time::interval(Duration::from_secs(1));
    let mut tick_count: u64 = 0;
    let ref mut ft = ForwardingTable::new(KEEPALIVE_TIMEOUT, MAX_MAC_AGING_TIMEOUT);

    loop {
        tokio::select! {
            s = socket.recv_from(&mut buf_sock) => match s {
                Ok((n, remote_addr)) => {
                    let data = &buf_sock[0..n];
                    if n < control::MIN_FRAME_SIZE {
                        if data == control::HELLO_PACKET {
                            info!("HELLO_PACKET arrives: {:?}", remote_addr);
                            ft.update_or_insert_nexthop(&remote_addr);
                            continue;
                        }

                        if data == control::KEEPALIVE_PACKET {
                            trace!("KEEPALIVE_PACKET arrives: {:?}", remote_addr);
                            ft.update_or_insert_nexthop(&remote_addr);
                            let _ = socket.send_to(control::KEEPALIVE_PACKET, remote_addr).await;
                            continue;
                        }

                        if data == control::BYE_PACKET {
                            info!("BYE_PACKET arrives: {:?}", remote_addr);
                            ft.remove_nexthop(&remote_addr);
                            continue;
                        }

                        warn!("Warning: unknown control packet: {:?}", data);
                    } else {
                        let src_mac = control::MacAddress::new(data[6..12].to_vec());
                        ft.mac_learning(&src_mac, &remote_addr);

                        let _ = tap_tx.write(data).await;
                        let _ = tap_tx.flush().await;
                    }
                },
                Err(e) => {
                    error!("Error: {:?}", e);
                    break;
                }
            },
            n = tap_rx.read(&mut buf_tap) => match n {
                Ok(n) => {
                    let data = &buf_tap[0..n];

                    if ipv6_filter && data[12..14] == [0x86, 0xdd] {
                        trace!("[filter ipv6 packet]\n{}", data.to_hex(16));
                        continue
                    }

                    let dst_mac = control::MacAddress::new(data[0..6].to_vec());
                    for addr in ft.get_nexthop(&dst_mac) {
                        let _ = socket.send_to(data, addr).await;
                    }
                },
                Err(e) => {
                    error!("{:?}", e);
                    break;
                }
            },
            _ = interval.tick() => {
                tick_count += 1;

                if tick_count % control::KEEPALIVE_TIMEOUT == 0 {
                    trace!("remove expired nexhops");
                    ft.remove_expired_nexthop();
                }

                if tick_count % control::MAX_MAC_AGING_TIMEOUT == 0 {
                    trace!("remove expired MAC entries");
                    ft.remove_expired_mac();
                }
            }
        }
    }
    Ok(())
}


pub fn main(listen_addr: &str, tap_name: &str, mac: MacAddress, tap_network_address: IPAddress, ipv6_filter: bool) {
    let runtime = Runtime::new().unwrap();
    let _ = runtime.block_on(server(listen_addr, tap_name, mac, tap_network_address, ipv6_filter));
    runtime.shutdown_timeout(Duration::from_secs(0));
}