//! Linux TAP interface creation and programming API module
//!
//! MAC address, IP address , Netmask, Broadcast address, interface operational status(UP/DOWN),
//! MTU, Owner ID & Group ID control programming API are introduced and working in Tokio async
//! programming environment.
//!

use std::cmp::min;
use std::os::unix::io::AsRawFd;
use libc;
use std::path::Path;
use tokio::fs::{File, OpenOptions};

const IFF_TAP: u32 = 0x0002;
const IFF_NO_PI: u32 = 0x1000;

const IFF_UP: u32 = 0x0001;
const IFF_RUNNING: u32 = 0x0040;

const TUNSETIFF: u32 = 0x400454ca;
const TUNSETOWNER: u32 = 0x400454cc;
const TUNSETGROUP: u32 = 0x400454ce;

const SIOCSIFHWADDR: u32 = 0x8924;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFBRDADDR: u32 = 0x891a;
const SIOCSIFNETMASK: u32 = 0x891c;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCSIFMTU: u32 = 0x8922;


const AF_INET: u32 = 0x02;
const AF_LOCAL: u32 = 0x01;

const MAX_NAME_LENGTH: usize = 16;
const MAX_FIELD_LENGTH: usize = 24;
const MAX_DATA_LENGTH: usize = MAX_NAME_LENGTH + MAX_FIELD_LENGTH;

#[repr(C)]
#[derive(Debug)]
/// Data structure to keep internal tun/tap FD, name, internal socket to
/// communication between the Linux userspace and kernel space.
/// TAP async read/write data capability with File type - read/write separate instances to avoid
/// a potential async loop blocking issue.
pub struct LinuxTapInterface {
    fd: i32,
    file: (File, File),
    socket: i32,
    name: [u8; MAX_NAME_LENGTH],
}

/// Drop trait to close an opened socket automatically at the end of the socket variable life scope.
impl Drop for LinuxTapInterface {
    fn drop(&mut self) {
        unsafe { libc::close(self.socket) };
    }
}

impl LinuxTapInterface {
    /// Return a MacAddress object with the given mac address in vector format.
    ///
    /// # Arguments
    ///
    /// * `value` - An vector that holds each mac value in u8 type.
    ///
    /// # Example
    /// ```
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use acton::linuxtap::LinuxTapInterface;
    /// use futures::stream::TryStreamExt;
    /// use rtnetlink::new_connection;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-1";
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///
    ///     let mut links = handle.link().get().match_name(tap_name.to_string()).execute();
    ///
    ///     assert!(links.try_next().await.unwrap().is_some(), "not found tap interface: '{}'", tap_name);
    ///     assert!(links.try_next().await.unwrap().is_none(), "multiple tap interfaces exist");
    /// });
    /// ```
    pub async fn new(name: &str) -> Result<Self, String> {
        let device_path = Path::new("/dev/net/tun");
        let file = OpenOptions::new().write(true).read(true).open(device_path).await;
        let file_rx = match file {
            Ok(file) => file,
            Err(e) => {
                let emsg = format!("Error: {:?}", e);
                error!("{}", emsg);
                return Err(emsg);
            }
        };
        let file_tx = file_rx.try_clone().await.unwrap();

        let req = LinuxTapInterface {
            fd: file_tx.as_raw_fd(),
            file: (file_tx, file_rx),
            // file: File::from_std(file),
            socket: unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)
            },
            name: {
                let mut data = [0u8; MAX_NAME_LENGTH];
                let length = min(name.len(), MAX_NAME_LENGTH);
                data[..length].copy_from_slice(name[..length].as_bytes());
                data
            },
        };

        // let mut flag: [u8; 4] = 0x1043u32.to_be_bytes();
        let mut flag: [u8; 4] = (IFF_NO_PI | IFF_TAP).to_be_bytes();
        flag.reverse();

        let mut data: [u8; MAX_DATA_LENGTH] = [0u8; MAX_DATA_LENGTH];
        data[..MAX_NAME_LENGTH].copy_from_slice(&req.name);
        data[MAX_NAME_LENGTH..MAX_NAME_LENGTH + 4].copy_from_slice(&flag);


        let result = unsafe { libc::ioctl(req.fd, TUNSETIFF as libc::c_ulong, &mut data) };

        if result < 0 {
            return Err(String::from("fail to create tap interface"));
        }

        Ok(req)
    }

    /// Return a ioctl data object with the given ipv4 address in bytes format.
    ///
    /// # Arguments
    ///
    /// * `address` - ip v4 address value of &[u8; 4] type.
    ///
    fn address_type(&mut self, address: &[u8; 4]) -> [u8; MAX_DATA_LENGTH] {
        let mut family = (AF_INET as u32).to_be_bytes();
        family.reverse();

        let sa_family_start_index = MAX_NAME_LENGTH;
        let sa_family_end_index = sa_family_start_index + 4;
        let sa_address_start_index = sa_family_end_index;
        let sa_address_end_index = sa_address_start_index + 4;

        let mut data: [u8; MAX_DATA_LENGTH] = [0u8; MAX_DATA_LENGTH];

        data[..MAX_NAME_LENGTH].copy_from_slice(&self.name);
        data[sa_family_start_index..sa_family_end_index].copy_from_slice(&family);
        data[sa_address_start_index..sa_address_end_index].copy_from_slice(&address[0..4]);

        data
    }

    /// Return a ioctl data object with the given ethernet mac address in bytes format.
    ///
    /// # Arguments
    ///
    /// * `address` - ethernet mac address value of &[u8; 6] type.
    ///
    fn mac_type(&mut self, address: &[u8; 6]) -> [u8; MAX_DATA_LENGTH] {
        let mut family = (AF_LOCAL as u16).to_be_bytes();
        family.reverse();

        let sa_family_start_index = MAX_NAME_LENGTH;
        let sa_family_end_index = sa_family_start_index + 2;
        let sa_address_start_index = sa_family_end_index;
        let sa_address_end_index = sa_address_start_index + 6;

        let mut data: [u8; MAX_DATA_LENGTH] = [0u8; MAX_DATA_LENGTH];

        data[..MAX_NAME_LENGTH].copy_from_slice(&self.name);
        data[sa_family_start_index..sa_family_end_index].copy_from_slice(&family);
        data[sa_address_start_index..sa_address_end_index].copy_from_slice(&address[0..6]);

        data
    }

    #[allow(dead_code)]
    /// Return a ioctl data object with the given u16 value.
    ///
    /// # Arguments
    ///
    /// * `value` - u16 number value.
    ///
    fn u16_type(&mut self, value: u16) -> [u8; MAX_DATA_LENGTH] {
        let mut value = value.to_be_bytes();
        value.reverse();

        let mut data: [u8; MAX_DATA_LENGTH] = [0u8; MAX_DATA_LENGTH];

        data[..MAX_NAME_LENGTH].copy_from_slice(&self.name);
        data[MAX_NAME_LENGTH..MAX_NAME_LENGTH + 2].copy_from_slice(&value);

        data
    }

    /// Return a ioctl data object with the given u32 value.
    ///
    /// # Arguments
    ///
    /// * `value` - u32 number value.
    ///
    fn u32_type(&mut self, value: u32) -> [u8; MAX_DATA_LENGTH] {
        let mut value = value.to_be_bytes();
        value.reverse();

        let mut data: [u8; MAX_DATA_LENGTH] = [0u8; MAX_DATA_LENGTH];

        data[..MAX_NAME_LENGTH].copy_from_slice(&self.name);
        data[MAX_NAME_LENGTH..MAX_NAME_LENGTH + 4].copy_from_slice(&value);

        data
    }

    /// Return result code of running the ioctl command to set ipv4 address for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `address` - ipv4 address of &[u8; 4] type.
    ///
    /// # Example
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use std::str::FromStr;
    ///
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use rtnetlink::new_connection;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-2";
    ///     let tap_ip = "1.2.3.2";
    ///
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///
    ///     tap.set_address(&Ipv4Addr::from_str(tap_ip).unwrap().octets());
    ///
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///
    ///     let mut addresses = handle
    ///         .address()
    ///         .get()
    ///         .set_address_filter(IpAddr::from_str(tap_ip.clone()).unwrap())
    ///         .execute();
    ///     
    ///     let a = addresses.try_next().await;
    ///     assert!(a.is_ok(), "no address('{}') match", tap_ip.clone());
    ///     
    ///     let a = a.unwrap();
    ///     assert!(a.is_some(), "no address('{}') match", tap_ip.clone());
    /// });
    /// ```
    pub fn set_address(&mut self, address: &[u8; 4]) -> i32 {
        let mut data = self.address_type(address);
        unsafe { libc::ioctl(self.socket, SIOCSIFADDR as libc::c_ulong, &mut data) }
    }

    
    /// Return result code of running the ioctl command to set ipv4 broadcast address for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `address` - ipv4 broadcast address of &[u8; 4] type.
    ///
    /// # Example
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use std::str::FromStr;
    ///
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use rtnetlink::new_connection;
    /// use netlink_packet_route::address::Nla;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-3";
    ///     let tap_ip = "1.2.3.3";
    ///     let tap_brd = "1.2.3.255";
    ///
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///     
    ///     tap.set_address(&Ipv4Addr::from_str(tap_ip).unwrap().octets());
    ///     tap.set_brd_address(&Ipv4Addr::from_str(tap_brd).unwrap().octets());
    ///     
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///     
    ///     let mut addresses = handle
    ///         .address()
    ///         .get()
    ///         .set_address_filter(IpAddr::from_str(tap_ip.clone()).unwrap())
    ///         .execute();
    ///     
    ///     let a = addresses.try_next().await;
    ///     assert!(a.is_ok(), "no address('{}') match", tap_ip.clone());
    ///     
    ///     let a = a.unwrap();
    ///     assert!(a.is_some(), "no address('{}') match", tap_ip.clone());
    ///     
    ///     let address_message = a.unwrap();
    ///     let mut nl_address_fields = address_message.nlas.iter()
    ///         .filter_map(|v| {
    ///             match v {
    ///                 Nla::Broadcast(ip) => Some(ip),
    ///                 _ => None,
    ///             }
    ///         });
    ///     
    ///     let brd = nl_address_fields.next().unwrap();
    ///     let nl_brd = Ipv4Addr::from([brd[0], brd[1], brd[2], brd[3]]).to_string();
    ///     
    ///     assert_eq!(tap_brd.to_string(), nl_brd);    
    /// });
    /// ```
    pub fn set_brd_address(&mut self, address: &[u8; 4]) -> i32 {
        let mut data = self.address_type(address);
        unsafe { libc::ioctl(self.socket, SIOCSIFBRDADDR as libc::c_ulong, &mut data) }
    }

    /// Return result code of running the ioctl command to set ipv4 netmask for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `address` - ipv4 netmask address of &[u8; 4] type.
    ///
    /// # Example
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use std::str::FromStr;
    ///
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use rtnetlink::new_connection;
    /// use netlink_packet_route::address::Nla;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-4";
    ///     let tap_network = "1.2.3.4/24";
    ///     
    ///     let ipaddr = ipaddress::ipv4::new(tap_network).unwrap();
    ///     let tap_ip = ipaddr.to_s();
    ///     
    ///     
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///     let tap_address = Ipv4Addr::from_str(ipaddr.to_s().as_str()).unwrap().octets();
    ///     let tap_netmask = Ipv4Addr::from_str(ipaddr.netmask().to_s().as_str()).unwrap().octets();
    ///     let tap_broadcast = Ipv4Addr::from_str(ipaddr.broadcast().to_s().as_str()).unwrap().octets();
    ///     
    ///     tap.set_address(&tap_address);
    ///     tap.set_brd_address(&tap_broadcast);
    ///     tap.set_netmask_address(&tap_netmask);
    ///     
    ///     
    ///     let address_prefix_len = {
    ///         let (connection, handle, _) = new_connection().unwrap();
    ///         tokio::spawn(connection);
    ///     
    ///         let mut addresses = handle
    ///             .address()
    ///             .get()
    ///             .set_address_filter(IpAddr::from_str(tap_ip.as_str()).unwrap())
    ///             .execute();
    ///     
    ///         let a = addresses.try_next().await;
    ///         assert!(a.is_ok(), "no address('{}') match", tap_network.clone());
    ///     
    ///         let a = a.unwrap();
    ///         assert!(a.is_some(), "no address('{}') match", tap_network.clone());
    ///     
    ///         let address_message = a.unwrap();
    ///     
    ///         address_message.header.prefix_len as usize
    ///     };
    ///     
    ///     assert_eq!(ipaddr.prefix.num, address_prefix_len);    
    /// });
    /// ```
    pub fn set_netmask_address(&mut self, address: &[u8; 4]) -> i32 {
        let mut data = self.address_type(address);
        unsafe { libc::ioctl(self.socket, SIOCSIFNETMASK as libc::c_ulong, &mut data) }
    }

    /// Return result code of running the ioctl command to set mac address for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `address` - mac address of &[u8; 6] type.
    ///
    /// # Example
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use std::str::FromStr;
    ///
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use rtnetlink::new_connection;
    /// use netlink_packet_route::link::nlas::Nla;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-5";
    ///     let tap_mac: [u8; 6] = [0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd];
    ///     
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///     
    ///     tap.set_mac_address(&tap_mac);
    ///     
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///     
    ///     let mut links = handle.link().get().match_name(tap_name.to_string()).execute();
    ///     
    ///     let link_message = links.try_next().await.unwrap().unwrap();
    ///     
    ///     let mut link = link_message.nlas.iter()
    ///         .filter_map(|v| {
    ///             match v {
    ///                 Nla::Address(addr) => Some(addr),
    ///                 _ => None
    ///             }
    ///         });
    ///     
    ///     let nl_mac = link.next().unwrap();
    ///     
    ///     assert_eq!(tap_mac.to_vec(), nl_mac.to_vec());
    /// });
    /// ```
    pub fn set_mac_address(&mut self, mac: &[u8; 6]) -> i32 {
        let mut data = self.mac_type(mac);
        unsafe { libc::ioctl(self.socket, SIOCSIFHWADDR as libc::c_ulong, &mut data) }
    }

    /// send ioctl command to set tap interface up.
    ///
    /// # Example
    /// ```
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use rtnetlink::new_connection;
    /// use netlink_packet_route::{IFF_LOWER_UP, IFF_RUNNING, IFF_UP};
    ///
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-6";
    ///
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///
    ///     tap.set_up();
    ///
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///
    ///     let mut links = handle.link().get().match_name(tap_name.to_string()).execute();
    ///     let link = links.try_next().await.unwrap();
    ///
    ///     assert!(link.is_some(), "not found tap interface: '{}'", tap_name);
    ///
    ///     let link_message = link.unwrap();
    ///
    ///     assert_eq!(link_message.header.flags & IFF_UP as u32, IFF_UP, "tap interface is not up");
    ///     assert_eq!(link_message.header.flags & IFF_RUNNING as u32, IFF_RUNNING, "tap interface is not running");
    ///     assert_eq!(link_message.header.flags & IFF_LOWER_UP as u32, IFF_LOWER_UP, "tap interface is not lower_up");
    /// });
    /// ```
    pub fn set_up(&mut self) -> i32 {
        let mut data = self.u32_type(IFF_RUNNING | IFF_UP | IFF_NO_PI | IFF_TAP);
        unsafe { libc::ioctl(self.socket, SIOCSIFFLAGS as libc::c_ulong, &mut data) }
    }

    /// Return result code of running the ioctl command to set mtu size for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `mtu` - mtu size.
    ///
    /// # Example
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    /// use std::str::FromStr;
    ///
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use netlink_packet_route::link::nlas::Nla;
    /// use rtnetlink::new_connection;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-7";
    ///     let tap_mtu = 1350;
    ///     
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///     
    ///     tap.set_mtu(tap_mtu);
    ///     
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///     
    ///     let mut links = handle.link().get().match_name(tap_name.to_string()).execute();
    ///     
    ///     let link_message = links.try_next().await.unwrap().unwrap();
    ///     
    ///     let mut link = link_message.nlas.iter()
    ///         .filter_map(|v| {
    ///             match v {
    ///                 Nla::Mtu(mtu) => Some(mtu),
    ///                 _ => None
    ///             }
    ///         });
    ///     
    ///     let nl_mtu = link.next().unwrap();
    ///     
    ///     assert_eq!(tap_mtu, *nl_mtu);
    /// });
    /// ```
    pub fn set_mtu(&mut self, mtu: u32) -> i32 {
        let mut data = self.u32_type(mtu);
        unsafe { libc::ioctl(self.socket, SIOCSIFMTU as libc::c_ulong, &mut data) }
    }

    /// Return result code of running the ioctl command to set owner uid for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `owner` - user id.
    ///
    /// # Example
    /// ```
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use netlink_packet_route::link::nlas::{Info, InfoData, Nla};
    /// use rtnetlink::new_connection;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-8";
    ///     let tap_user_id = 1000;
    ///     
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///     
    ///     tap.set_owner(tap_user_id);
    ///     
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///     
    ///     let mut links = handle.link().get().match_name(tap_name.to_string()).execute();
    ///     let link_message = links.try_next().await.unwrap().unwrap();
    ///     
    ///     let mut link = link_message.nlas.iter()
    ///         .filter_map(|v| {
    ///             match v {
    ///                 Nla::Info(info) => Some(info),
    ///                 _ => None
    ///             }
    ///         });
    ///     
    ///     let nl_info = link.next().unwrap();
    ///     
    ///     let mut nl_tun_data = nl_info.iter().filter_map(|v| {
    ///         match v {
    ///             Info::Data(data) => {
    ///                 match data {
    ///                     InfoData::Tun(data) => Some(data),
    ///                     _ => None
    ///                 }
    ///             }
    ///             _ => None
    ///         }
    ///     });
    ///
    ///     let data = nl_tun_data.next().unwrap();
    ///     let data_chunks = data.chunks_exact(8);
    ///     
    ///     for c in data_chunks {
    ///         let field_type = u16::from_le_bytes([c[2], c[3]]);
    ///         if field_type == 1u16 { ///     GID
    ///             let uid = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
    ///             assert_eq!(tap_user_id, uid);
    ///             break;
    ///         }
    ///     }
    /// });
    /// ```
    pub fn set_owner(&mut self, owner: u32) -> i32 {
        unsafe { libc::ioctl(self.fd, TUNSETOWNER as libc::c_ulong, owner as u64) }
    }

    /// Return result code of running the ioctl command to set owner uid for a tap interface.
    ///
    /// # Arguments
    ///
    /// * `owner` - user id.
    ///
    /// # Example
    /// ```
    /// use tokio;
    /// use tokio::runtime::Runtime;
    /// use futures::stream::TryStreamExt;
    ///
    /// use netlink_packet_route::link::nlas::{Info, InfoData, Nla};
    /// use rtnetlink::new_connection;
    /// use acton::linuxtap::LinuxTapInterface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-9";
    ///     let tap_group_id = 1000;
    ///     
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///     
    ///     tap.set_group(tap_group_id);
    ///     
    ///     let (connection, handle, _) = new_connection().unwrap();
    ///     tokio::spawn(connection);
    ///     
    ///     let mut links = handle.link().get().match_name(tap_name.to_string()).execute();
    ///     let link_message = links.try_next().await.unwrap().unwrap();
    ///     
    ///     let mut link = link_message.nlas.iter()
    ///         .filter_map(|v| {
    ///             match v {
    ///                 Nla::Info(info) => Some(info),
    ///                 _ => None
    ///             }
    ///         });
    ///     
    ///     let nl_info = link.next().unwrap();
    ///     
    ///     let mut nl_tun_data = nl_info.iter().filter_map(|v| {
    ///         match v {
    ///             Info::Data(data) => {
    ///                 match data {
    ///                     InfoData::Tun(data) => Some(data),
    ///                     _ => None
    ///                 }
    ///             }
    ///             _ => None
    ///         }
    ///     });
    ///     
    ///     let data = nl_tun_data.next().unwrap();
    ///     let data_chunks = data.chunks_exact(8);
    ///     
    ///     for c in data_chunks {
    ///         let field_type = u16::from_le_bytes([c[2], c[3]]);
    ///         if field_type == 2u16 { ///     GID
    ///             let gid = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
    ///             assert_eq!(tap_group_id, gid);
    ///             break;
    ///         }
    ///     }
    /// });
    /// ```    
    pub fn set_group(&mut self, group: u32) -> i32 {
        unsafe { libc::ioctl(self.fd, TUNSETGROUP as libc::c_ulong, group as u64) }
    }

    /// Return tx and rx file instance.
    ///
    /// # Example
    /// ```
    /// use std::time::Duration;
    ///
    /// use tokio::io::{AsyncReadExt, AsyncWriteExt};
    /// use tokio::select;
    /// use tokio::time::sleep;
    /// use tokio::runtime::Runtime;
    /// use tokio::sync::mpsc::{Receiver, Sender};
    ///
    /// use pnet::datalink::{Channel, MacAddr};
    /// use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    /// use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    /// use pnet::packet::{MutablePacket, Packet};
    ///
    /// use acton::linuxtap::LinuxTapInterface;
    /// use acton::linuxinterface::raw_interface;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let tap_name = "tap1234-10";
    ///
    ///     // create tap interface
    ///     let mut tap = match LinuxTapInterface::new(tap_name).await {
    ///         Ok(tap) => tap,
    ///         Err(e) => {
    ///             panic!("{:?}", e);
    ///         }
    ///     };
    ///
    ///     // make tap port up
    ///     tap.set_up();
    ///
    ///
    ///     let (interface, mut port_tx, mut port_rx) = raw_interface(tap_name.clone(), true);
    ///     // loop tap interface
    ///     tokio::spawn(async move {
    ///         loop {
    ///             let packet = port_rx.recv().await.unwrap();
    ///             port_tx.send(packet).await;
    ///         }
    ///     });
    ///
    ///     // ethernet/arp packet build-up
    ///     let mut ethernet_buffer = [0u8; 42];
    ///     let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ///
    ///     ethernet_packet.set_destination(MacAddr::broadcast());
    ///     ethernet_packet.set_source(interface.mac.unwrap());
    ///     ethernet_packet.set_ethertype(EtherTypes::Arp);
    ///
    ///     let mut arp_buffer = [0u8; 28];
    ///     let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    ///
    ///     arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    ///     arp_packet.set_protocol_type(EtherTypes::Ipv4);
    ///     arp_packet.set_hw_addr_len(6);
    ///     arp_packet.set_proto_addr_len(4);
    ///     arp_packet.set_operation(ArpOperations::Request);
    ///     arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    ///     arp_packet.set_sender_proto_addr("1.2.3.4".parse().unwrap());
    ///     arp_packet.set_target_hw_addr(MacAddr::zero());
    ///     arp_packet.set_target_proto_addr("1.2.3.5".parse().unwrap());
    ///
    ///     ethernet_packet.set_payload(arp_packet.packet_mut());
    ///
    ///
    ///     let (tap_tx, tap_rx) = tap.get_file();
    ///
    ///     let _ = tap_tx.write_all(ethernet_packet.packet()).await;
    ///
    ///     println!("Sent ARP request");
    ///     println!("arp tx: {:02x?}", ethernet_packet.packet());
    ///
    ///     let rx_buf = &mut [0u8; 2000];
    ///
    ///     /// check if sent arp packet is looped back and arrives?
    ///     loop {
    ///         select! {
    ///             n = tap_rx.read(rx_buf) => match n {
    ///                 Ok(n) => {
    ///                     if n == 0 {
    ///                         panic!("tap rx error");
    ///                     }
    ///
    ///                     let packet = &rx_buf[0..n];
    ///
    ///                     if ethernet_packet.packet() == packet {
    ///                         println!("arp packet rx: {:02x?}", packet);
    ///                         break;
    ///                     } else {
    ///                         println!("other packet rx - skip: {:02x?}", packet);
    ///                     }
    ///
    ///                 },
    ///                 Err(e) => panic!("tap rx error: {:?}", e),
    ///             },
    ///             _ = sleep(Duration::from_secs(3)) => { 
    ///                 panic!("tap rx timeout");
    ///             }
    ///         }
    ///     }
    /// });
    /// ```
    pub fn get_file(&mut self) -> &mut (File, File) {
        &mut self.file
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::runtime::Runtime;

    use eui48::MacAddress;

    use bytes::{BufMut, BytesMut};

    use super::*;

    #[test]
    fn test_tap_rx_tx() {
        let rt = Runtime::new().unwrap();

        let _ = rt.block_on(async move {
            let tap_name = "tap4321";

            let local_mac = MacAddress::parse_str("00:01:02:03:04:05").expect("Parse error {}");
            let remote_mac = MacAddress::parse_str("00:0a:0b:0c:0d:0e").expect("Parse error {}");

            let local_address = Ipv4Addr::from_str("192.168.255.1").unwrap().octets();
            let remote_address = Ipv4Addr::from_str("192.168.255.2").unwrap().octets();
            let netmask = Ipv4Addr::from_str("255.255.255.0").unwrap().octets();
            let broadcast = Ipv4Addr::from_str("192.168.255.255").unwrap().octets();

            let mut arp_request = BytesMut::new();
            {
                arp_request.put_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
                arp_request.put_slice(remote_mac.as_bytes());
                arp_request.put_slice(&[0x08, 0x06]);
                arp_request.put_slice(&[0x00, 0x01]);
                arp_request.put_slice(&[0x08, 0x00]);
                arp_request.put_slice(&[0x06]);
                arp_request.put_slice(&[0x04]);
                arp_request.put_slice(&[0x00, 0x01]); // arp request
                arp_request.put_slice(remote_mac.as_bytes());
                arp_request.put_slice(&remote_address as &[u8]);
                arp_request.put_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                arp_request.put_slice(&local_address as &[u8]);
            }

            let mut arp_response = BytesMut::new();
            {
                arp_response.put_slice(remote_mac.as_bytes());
                arp_response.put_slice(local_mac.as_bytes());
                arp_response.put_slice(&[0x08, 0x06]);
                arp_response.put_slice(&[0x00, 0x01]);
                arp_response.put_slice(&[0x08, 0x00]);
                arp_response.put_slice(&[0x06]);
                arp_response.put_slice(&[0x04]);
                arp_response.put_slice(&[0x00, 0x02]); // arp response
                arp_response.put_slice(local_mac.as_bytes());
                arp_response.put_slice(&local_address as &[u8]);
                arp_response.put_slice(remote_mac.as_bytes());
                arp_response.put_slice(&remote_address as &[u8]);
            }
            {
                let mut tap = match LinuxTapInterface::new(tap_name).await {
                    Ok(tap) => tap,
                    Err(e) => {
                        panic!("fail to create tap interface: {}", e);
                    }
                };

                let mut local_mac2 = [0u8; 6];
                local_mac2.copy_from_slice(local_mac.as_bytes());

                tap.set_address(&local_address);
                tap.set_brd_address(&netmask);
                tap.set_netmask_address(&broadcast);
                tap.set_mac_address(&local_mac2);
                tap.set_owner(1000);
                tap.set_group(1000);
                tap.set_up();

                let (tap_tx, tap_rx) = tap.get_file();

                let _ = tap_tx.write_all(&arp_request[..]).await;

                let rx_buf = &mut [0u8; 2000];
                let n = tap_rx.read(rx_buf).await.unwrap();

                let packet = BytesMut::from(&rx_buf[0..n]);

                assert_eq!(arp_response.eq(&packet), true);
            }
        });
    }
}
