//! Ethernet over udp client implementation
//!

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::time;
use tokio::signal;
use tokio::time::sleep;

use std::{net::SocketAddr};
use std::process::exit;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use eui48::MacAddress;
use ipaddress::IPAddress;
use nom::HexDisplay;

use crate::control::Error;
use crate::control;
use crate::linuxtap::LinuxTapInterface;


/// Run ethernet p2mp tunnel over ip client.
///
/// # Arguments
///
/// * `server_address` - server address:port str.
/// * `tap_name` - name of tap interface that will be created.
/// * `mac` - tap interface mac.
/// * `tap_network_address` - tap interface ip network.
/// * `ipv6_filter` - filter any ipv6 packet at tap interface input path (mainly for unit/doc test purpose)
///
/// # Example
/// ```
/// use std::str::FromStr;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// use tokio::runtime::Runtime;
/// use tokio::select;
/// use tokio::time::sleep;
///
/// use tokio::net::UdpSocket;
///
/// use acton::linuxtap::LinuxTapInterface;
/// use acton::linuxinterface::raw_interface;
/// use acton::client;
/// use hex;
/// use nom::HexDisplay;
///
/// use std::time::Duration;
/// use eui48::{MacAddress, ParseError};
/// use ipaddress::IPAddress;
///
/// Runtime::new().unwrap().block_on(async {
///     tokio::spawn(async move {
///         let socket = UdpSocket::bind("127.0.0.1:9090").await.unwrap();
///         let buf = &mut [0u8; 2000];
///         loop {
///             let (n, client_addr) = socket.recv_from(buf).await.unwrap();
///             let _ = socket.send_to(&buf[0..n], client_addr).await;
///         }
///     });
///
///     let tap_name = "tap-client";
///
///     tokio::spawn(async move {
///         client::client(
///             "127.0.0.1:9090",
///             tap_name.clone(),
///             MacAddress::from_str("00:01:02:03:04:a5").unwrap(),
///             ipaddress::ipv4::new("1.2.3.4/24").unwrap(),
///             true,
///         ).await.unwrap();
///     });
///
///     sleep(Duration::from_secs(1)).await;
///
///     let (_interface, port_tx, mut port_rx) = raw_interface(tap_name.clone(), true);
///
///     let packet1 = hex::decode("ffffffffffff4a60b989d99a080600010800060400014a60b989d99a0102030400000000000001020305").unwrap();
///     let packet1 = bytes::Bytes::from(packet1);
///     let _ = port_tx.send(packet1.clone()).await;
///
///     let packet2 = port_rx.recv().await.unwrap();
///
///     println!("packet1:\n{}", packet1.to_hex(16));
///     println!("packet2:\n{}", packet2.to_hex(16));
///
///     assert_eq!(packet1, packet2);
///
///     println!("...done...");
/// });
/// ```
pub async fn client(server_address: &str, tap_name: &str, mac: MacAddress, tap_network_address: IPAddress, ipv6_filter: bool) -> Result<(), Error> {
    info!("client starts");

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


    let remote_addr = server_address.parse::<SocketAddr>().unwrap();
    let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();

    let socket = UdpSocket::bind(local_addr).await?;
    socket.connect(&remote_addr).await?;

    info!("connecting: {:?}", remote_addr);

    let mut buf_tap = [0u8; control::MAX_FRAME_SIZE];
    let mut buf_sock = [0u8; control::MAX_FRAME_SIZE];

    let mut interval = time::interval(Duration::from_secs(1));
    let mut hello_elapsed_time: u64 = 0;
    let mut keeplive_elapsed_time: u64 = 0;
    let mut tick: u64 = 0;

    trace!("send 1st HELLO_PACKET and waiting...: {:?}", remote_addr);
    let _ = socket.send(control::HELLO_PACKET).await;

    let mut is_connecred = false;
    loop {
        tokio::select! {
            n = tap_rx.read(&mut buf_tap) => match n {
                Ok(n) => {
                    if n == 0 {
                        trace!("socket closed.");
                        break;
                    }

                    let data = &buf_tap[0..n];

                    if ipv6_filter && data[12..14] == [0x86, 0xdd] {
                        trace!("[filter ipv6 packet]\n{}", data.to_hex(16));
                        continue
                    }

                    let _ = socket.send(data).await;
                },
                Err(e) => {
                    error!("{:?}", e);
                    break;
                }
            },
            n = socket.recv(&mut buf_sock) => match n {
                Ok(n) => {
                    if n < control::MIN_FRAME_SIZE {
                        let data = &buf_sock[0..n];

                        if data == control::HELLO_PACKET {
                            trace!("HELLO_PACKET arrives: {:?}", remote_addr);
                            info!("connected: {:?}", remote_addr);
                            is_connecred = true;
                            continue;
                        }

                        if data == control::KEEPALIVE_PACKET {
                            trace!("Keepalive arrives and reset keepalive_elasped_time");
                            keeplive_elapsed_time = 0;
                            continue;
                        }

                        warn!("Warning: unknown control packet: {:?}", data);
                        continue;
                    }

                    let _ = tap_tx.write_all(&buf_sock[0..n]).await;
                    let _ = tap_tx.flush().await;
                },
                Err(e) => {
                    error!("{:?}", e);
                    break;
                }
            },
            _ = interval.tick() => {
                tick += 1;

                if is_connecred == false {
                    if tick % control::HELLO_INTERVAL == 0 {
                        error!("no hello response from server -> send hello again to {:?}", remote_addr);
                        let _ = socket.send(control::HELLO_PACKET).await;
                    }

                    hello_elapsed_time += 1;

                    // keepalive timeout. exit
                    if hello_elapsed_time > control::HELLO_TIMEOUT {
                        info!("Hello timeout! - {:?}", remote_addr);
                        info!("Bye!");
                        break;
                    }
                }
                else {
                    if tick % control::KEEPALIVE_INTERVAL == 0 {
                        trace!("send keepalive({:?})", tick);
                        let _ = socket.send(control::KEEPALIVE_PACKET).await;
                    }

                    keeplive_elapsed_time += 1;

                    // keepalive timeout. exit
                    if keeplive_elapsed_time > control::KEEPALIVE_TIMEOUT {
                        info!("Keepalive timeout - Bye!");
                        break;
                    }
                }
            },
            _ = signal::ctrl_c() => {
                let _ = socket.send(control::BYE_PACKET).await;
                info!("Close session");

                sleep(Duration::from_secs(1)).await;

                break;
            }
        }
    }
    info!("client exits");
    Ok(())
}

/// Wrapper function to run ethernet p2mp tunnel over ip client in blocking mode.
///
/// # Arguments
///
/// * `tap_name` - name of tap interface that will be created.
/// * `server_address` - server address:port str.
/// * `mac` - tap interface mac.
/// * `tap_network_address` - tap interface ip network.
///
/// # Example
/// ```
/// use std::str::FromStr;
/// use std::thread;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// use tokio::runtime::Runtime;
/// use tokio::select;
/// use tokio::time::sleep;
///
/// use tokio::net::UdpSocket;
///
/// use acton::linuxtap::LinuxTapInterface;
/// use acton::linuxinterface::raw_interface;
/// use acton::client;
/// use hex;
/// use nom::HexDisplay;
///
/// use std::time::Duration;
/// use eui48::{MacAddress, ParseError};
/// use ipaddress::IPAddress;
///
/// let runtime = Runtime::new().unwrap();
/// runtime.block_on(async {
///     tokio::spawn(async move {
///         let socket = UdpSocket::bind("127.0.0.1:9091").await.unwrap();
///         let buf = &mut [0u8; 2000];
///         loop {
///             let (n, client_addr) = socket.recv_from(buf).await.unwrap();
///             let _ = socket.send_to(&buf[0..n], client_addr).await;
///         }
///     });
///
///     let tap_name = "tap-client-main";
///
///     thread::spawn( move || {
///         client::main(
///             "127.0.0.1:9091",
///             tap_name.clone(),
///             MacAddress::from_str("00:01:02:03:04:a6").unwrap(),
///             ipaddress::ipv4::new("1.2.4.5/24").unwrap(),
///             true,
///         );
///     });
///
///     sleep(Duration::from_secs(1)).await;
///
///     let (_interface, port_tx, mut port_rx) = raw_interface(tap_name.clone(), true);
///
///     let packet1 = hex::decode("ffffffffffff4a60b989d99a080600010800060400014a60b989d99a0102030400000000000001020305").unwrap();
///     let packet1 = bytes::Bytes::from(packet1);
///     let _ = port_tx.send(packet1.clone()).await;
///
///     let packet2 = port_rx.recv().await.unwrap();
///
///     println!("packet1:\n{}", packet1.to_hex(16));
///     println!("packet2:\n{}", packet2.to_hex(16));
///
///     assert_eq!(packet1, packet2);
///
///     println!("...done...");
/// });
/// runtime.shutdown_timeout(Duration::from_secs(0));
/// ```
pub fn main(server_address: &str, tap_name: &str, mac: MacAddress, tap_network_address: IPAddress, ipv6_filter: bool) {
    let runtime = Runtime::new().unwrap();
    let _ = runtime.block_on(client(server_address, tap_name, mac, tap_network_address, ipv6_filter));
    runtime.shutdown_timeout(Duration::from_secs(0));
}

