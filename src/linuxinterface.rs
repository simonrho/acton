//! Linux raw interface binding to send/receive raw ethernet frames
//!

use pnet::datalink::{Channel, NetworkInterface};

use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use bytes;
use nom::HexDisplay;

/// Bind interface to socket and return tx/tx channel to send/receive packet from interface.
///
/// # Arguments
///
/// * `name` -  interface name
/// * `ipv6_filter` - filter any ipv6 packet at tap interface input path (mainly for unit/doc test purpose)
///
/// # Example
/// ```
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
/// use tokio::runtime::Runtime;
/// use tokio::select;
///
/// use acton::linuxtap::LinuxTapInterface;
/// use acton::linuxinterface::raw_interface;
///
/// use hex;
/// use nom::HexDisplay;
/// use tokio::time::sleep;
///
/// use std::time::Duration;
///
/// Runtime::new().unwrap().block_on(async {
///     let tap_name = "tap1234-raw";
///
///     //  create tap interface
///     let mut tap = LinuxTapInterface::new(tap_name).await.unwrap();
///     tap.set_up();
///     let (tap_tx, tap_rx) = tap.get_file();
///
///     let (_interface, port_tx, mut port_rx) = raw_interface(tap_name.clone(), true);
///
///     let packet1 = hex::decode("ffffffffffff4a60b989d99a080600010800060400014a60b989d99a0102030400000000000001020305").unwrap();
///     let _ = tap_tx.write_all(packet1.as_slice()).await;
///
///     let packet2 = port_rx.recv().await.unwrap();
///
///     println!("packet1:\n{}", packet1.to_hex(16));
///     println!("packet2:\n{}", packet2.to_hex(16));
///
///     assert_eq!(packet1, packet2);
///
///     let packet1 = bytes::Bytes::from(packet1);
///     port_tx.send(packet1.clone()).await.unwrap();
///
///     let buf = &mut [0u8; 2000];
///
///     loop {
///         select! {
///             n = tap_rx.read(buf) => match n {
///                 Ok(n) => {
///                     let packet2 = &buf[0..n];
///                     if packet1.to_vec() != packet2.to_vec() { continue }
///                     break;
///                 }
///                 Err(_) => panic!("read error"),
///             },
///             _ = sleep(Duration::from_secs(3)) => panic!("timeout")
///         }
///     }
///
///     println!("...done...");
/// });
/// ```
pub fn raw_interface(name: &str, ipv6_filter: bool) -> (NetworkInterface, Sender<bytes::Bytes>, Receiver<bytes::Bytes>) {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == name.to_string())
        .unwrap();

    let (mut sender, mut receiver) =
        match pnet::datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };


    let (tx1, rx) = mpsc::channel::<bytes::Bytes>(10000);
    let (tx, mut rx2) = mpsc::channel::<bytes::Bytes>(10000);

    tokio::task::spawn_blocking(move || {
        loop {
            let packet = match receiver.next() {
                Ok(packet) => {
                    if ipv6_filter && packet[12..14] == [0x86, 0xdd] {
                        trace!("[filter ipv6 packet]\n{}", packet.to_hex(16));
                        continue
                    }
                    packet
                },
                Err(e) => {
                    println!("ERROR: raw_interface: {:?}", e);
                    break;
                }
            };

            let data = bytes::Bytes::copy_from_slice(packet);
            match tx1.blocking_send(data) {
                Ok(_) => continue,
                Err(_) => break
            }
        }
    });

    tokio::task::spawn_blocking(move || {
        loop {
            let packet = match rx2.blocking_recv() {
                Some(packet) => packet,
                None => break
            };
            let _ = sender.send_to(&packet[..], None);
        }
    });

    (interface, tx, rx)
}

