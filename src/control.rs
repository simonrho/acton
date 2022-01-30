//! Minimal Mac learning and socket session management for L2 tunnel forwarding implementation
//!
//! Data struct and utility functions for the ethernet mac entry aging and next-hop (remote peer)
//! management are included.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use bytes::Buf;

/// The maximum ethernet frame buffer size
pub const MAX_FRAME_SIZE: usize = 1024 * 9;
/// The minimum ethernet frame size. Any frame that is shorter than this size will be treated
/// as a control packet.(HELLO, KEEPALIVE, BYE, and so on)
pub const MIN_FRAME_SIZE: usize = 14;

pub const BROADCAST_MAC_ADDRESS: u64 = 0xffff_ffff_ffff;
pub const MULTICAST_MAC_PREFIX_V4: u64 = 0x0100_5e00_0000;
pub const MULTICAST_MAC_PREFIX_V6: u64 = 0x3333_0000_0000;
pub const MULTICAST_MAC_ADDRESS_MASK_V4: u64 = 0xffff_ff80_0000;
pub const MULTICAST_MAC_ADDRESS_MASK_V6: u64 = 0xffff_0000_0000;

pub const MAX_MAC_COUNT: usize = 32_000;
pub const MAX_NEXTHOP_COUNT: usize = 3000;
pub const MAX_MAC_AGING_TIMEOUT: u64 = 600; // 5 minutes

pub const KEEPALIVE_TIMEOUT: u64 = 30;
pub const KEEPALIVE_INTERVAL: u64 = 10;
pub const KEEPALIVE_PACKET: &[u8] = "KEEPALIVE".as_bytes();
pub const HELLO_PACKET: &[u8] = "HELLO".as_bytes();
pub const BYE_PACKET: &[u8] = "BYE".as_bytes();

pub type Error = Box<dyn std::error::Error + Sync + Send>;
type MacValue = u64;

#[derive(Clone, Debug, Copy)]
/// A mac address of vector<u8> format is converted into an value of u64 and stored in the struct MacAddress
pub struct MacAddress {
    /// A mac address is stored in u64 format (MacValue type).
    value: MacValue,
}

impl MacAddress {
    /// Return a MacAddress object with the given mac address in vector format.
    ///
    /// # Arguments
    ///
    /// * `value` - An vector that holds each mac value in u8 type.
    ///
    /// # Example
    /// ```
    /// use acton::control::MacAddress;
    ///
    /// let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    /// assert_eq!(mac.get_value(), 0x000102030405u64);
    /// ```
    pub fn new(value: Vec<u8>) -> Self {
        let v = bytes::Bytes::from(value);
        let a = v.slice(0..2).get_u16();
        let b = v.slice(2..6).get_u32();
        let value = ((a as u64) << 32) + (b as u64);

        MacAddress {
            value
        }
    }

    /// Return a MacValue type value(actually it is u64) of mac address in the big-endian data packing format.
    ///
    /// # Example
    /// ```
    /// use acton::control::MacAddress;
    ///
    /// let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    /// assert_eq!(mac.get_value(), 0x000102030405u64);
    /// ```
    pub fn get_value(&self) -> MacValue {
        self.value.clone()
    }

    /// Return true if the mac address is boradcast mac address (all ones). Otherwise, return false.
    ///
    /// # Example
    /// ```
    /// use acton::control::MacAddress;
    /// let mac = MacAddress::new(vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    /// assert_eq!(mac.is_broadcast(), true);
    /// ```
    pub fn is_broadcast(&self) -> bool {
        self.value == BROADCAST_MAC_ADDRESS
    }

    /// Return true if the mac address is multicast mac address. Otherwise, return false.
    ///
    /// # Example
    /// ```
    /// use acton::control::MacAddress;
    /// let mac = MacAddress::new(vec![0x01, 0x00, 0x5e, 0x00, 0x01, 0x01]);
    /// assert_eq!(mac.is_multicast(), true);
    ///
    /// let mac = MacAddress::new(vec![0x33, 0x33, 0x00, 0x00, 0x00, 0x02]);
    /// assert_eq!(mac.is_multicast(), true);
    /// ```
    pub fn is_multicast(&self) -> bool {
        self.value & MULTICAST_MAC_ADDRESS_MASK_V4 == MULTICAST_MAC_PREFIX_V4 ||
            self.value & MULTICAST_MAC_ADDRESS_MASK_V6 == MULTICAST_MAC_PREFIX_V6
    }

    /// Return true if the mac address is unicast mac address. Otherwise, return false.
    ///
    /// # Example
    /// ```
    /// use acton::control::MacAddress;
    /// let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    /// assert_eq!(mac.is_unicast(), true);
    /// ```
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast() && !self.is_multicast()
    }
}

#[derive(Debug)]
/// Forwarding next-hop is composed of remote socket address including port number and timestamp
/// of an entry creation time.
pub struct NextHop {
    addr: SocketAddr,
    expiry_time: Instant,
}

impl NextHop {
    /// Return a NextHop object with the given nexthop value of `std::net::SocketAddr` type.
    ///
    /// A new next-hop SocketAddr value and its Instance value as the expiry time are stored.
    ///
    /// # Arguments
    ///
    /// * `addr` - remote peer address of std::net::SocketAddr type
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use acton::control::NextHop;
    ///
    /// let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    /// let nh = NextHop::new(addr, 300);
    ///
    /// assert_eq!(nh.get_addr(), addr);
    /// ```
    pub fn new(addr: SocketAddr, timeout: u64) -> Self {
        NextHop {
            addr,
            expiry_time: Instant::now() + Duration::from_secs(timeout),
        }
    }

    /// Update next-hop creation time with current Instant timestamp.
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use std::thread::sleep;
    /// use std::time::Duration;
    /// use acton::control::NextHop;
    ///
    /// let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    /// let mut nh = NextHop::new(addr, 1);
    ///
    /// sleep(Duration::from_secs(1));
    ///
    /// nh.update_expiry_time(1);
    /// assert_eq!(nh.is_expired(), false);
    /// ```
    pub fn update_expiry_time(&mut self, timeout: u64) {
        self.expiry_time = Instant::now() + Duration::from_secs(timeout);
    }

    /// Return true if aging time of a next-hop value is expired. Otherwise, return false.
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use std::thread::sleep;
    /// use std::time::{Instant, Duration};
    /// use acton::control::{NextHop, MAX_MAC_AGING_TIMEOUT};
    ///
    /// let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    /// let mut nh = NextHop::new(addr, 1);
    ///
    /// sleep(Duration::from_secs(1));
    ///
    /// assert_eq!(nh.is_expired(), true);
    /// ```
    pub fn is_expired(&self) -> bool {
        self.expiry_time < Instant::now()
    }

    /// Return a `std::net::SocketAddr` type value of ethernet frame forwarding next-hop.
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use acton::control::NextHop;
    ///
    /// let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    /// let nh = NextHop::new(addr, 30);
    ///
    /// assert_eq!(nh.get_addr(), addr);
    /// ```
    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }
}

#[derive(Debug)]
/// Mac entry, next-hop, aging time are kept in hashmap data structure.
pub struct ForwardingTable {
    /// mac entry aging timeout
    mac_aging_timeout: u64,
    /// mac entry and its next-hop is stored here and looked up later for network side forwarding (server to client).
    mac_table: HashMap<MacValue, NextHop>,
    // nexthop entry timeout
    nexthop_timeout: u64,
    /// Remote peer's socket address and timestamp information is used for socket session lifecycle management.
    nexthop_table: HashMap<SocketAddr, Instant>,
}

impl ForwardingTable {
    /// Return a new ForwardingTable object.
    ///
    /// # Example
    /// ```
    /// use acton::control::ForwardingTable;
    ///
    /// let nexthop_timeout = 30u64;
    /// let mac_aging_timeout = 300u64;
    /// let mt = ForwardingTable::new(nexthop_timeout, mac_aging_timeout);
    ///
    /// assert_eq!(mt.nexthop_count(), 0);
    /// assert_eq!(mt.mac_count(), 0);
    /// ```
    pub fn new(nexthop_timeout: u64, mac_aging_timeout: u64) -> ForwardingTable {
        ForwardingTable {
            nexthop_timeout: if nexthop_timeout == 0 { 1 } else { nexthop_timeout },
            mac_aging_timeout: if mac_aging_timeout == 0 { 1 } else { mac_aging_timeout },
            nexthop_table: HashMap::new(),
            mac_table: HashMap::new(),
        }
    }

    /// Return count of sock session
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use tokio::runtime::Runtime;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let mut mac_table = ForwardingTable::new(30, 300);
    ///
    ///     let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    ///     mac_table.update_or_insert_nexthop(&addr);
    ///     assert_eq!(mac_table.nexthop_count() == 1, true);
    /// });
    /// ```
    pub fn nexthop_count(&self) -> u64 {
        self.nexthop_table.len() as u64
    }

    /// Return the total count of existing sock sessions
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use tokio::runtime::Runtime;
    /// use acton::control::MacAddress;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let mut mac_table = ForwardingTable::new(30, 300);
    ///
    ///     let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    ///     let addr = "1.1.1.1:1234".parse::<SocketAddr>().unwrap();
    ///     mac_table.mac_learning(&mac, &addr);
    ///
    ///     let mac_count = mac_table.mac_count();
    ///
    ///     assert_eq!(mac_count == 1, true);
    /// });
    /// ```
    pub fn mac_count(&self) -> u64 {
        self.mac_table.len() as u64
    }


    /// Update the expiry timestamp of an existing socket session or create a new socket session.
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use tokio::runtime::Runtime;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let ref mut mac_table = ForwardingTable::new(30, 300);
    ///     assert_eq!(mac_table.nexthop_count() == 0, true);
    ///
    ///     let addr = "1.1.1.1:1234".parse::<SocketAddr>().unwrap();
    ///     mac_table.update_or_insert_nexthop(&addr);
    ///     assert_eq!(mac_table.nexthop_count() == 1, true);
    ///
    ///     let addr = "1.1.1.2:5678".parse::<SocketAddr>().unwrap();
    ///     mac_table.update_or_insert_nexthop(&addr);
    ///     assert_eq!(mac_table.nexthop_count() == 2, true);
    /// });
    /// ```
    pub fn update_or_insert_nexthop(&mut self, addr: &SocketAddr) {
        match self.nexthop_table.get_mut(&addr) {
            Some(created_time) => {
                *created_time = Instant::now() + Duration::from_secs(self.nexthop_timeout);
                trace!("renew socket session creation time: {:?}", addr);
            }
            None => {
                if self.nexthop_table.len() < MAX_NEXTHOP_COUNT {
                    self.nexthop_table.insert(*addr, Instant::now() + Duration::from_secs(self.nexthop_timeout));
                    info!("new socket session: {:?}", addr);
                } else {
                    error!("nexthop_table overflow!");
                }
            }
        };
    }

    /// Remove an existing sock entry
    ///
    /// # Arguments
    /// * `addr` - SocketAddr object that will be removed from the internal mac-table.
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use tokio::runtime::Runtime;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    ///
    ///     let mut mac_table = ForwardingTable::new(30, 300);
    ///     mac_table.update_or_insert_nexthop(&addr);
    ///     assert_eq!(mac_table.nexthop_count() == 1, true);
    ///
    ///     mac_table.remove_nexthop(&addr);
    ///     assert_eq!(mac_table.nexthop_count() == 0, true);
    /// });
    /// ```
    pub fn remove_nexthop(&mut self, addr: &SocketAddr) {
        let mut mac_list = Vec::new();
        for (mac, nexthop) in self.mac_table.iter() {
            if nexthop.get_addr() == *addr {
                mac_list.push(mac.clone());
            }
        }

        trace!("remove mac entries pointing to the deleted socket session {:?}", addr);
        for m in mac_list {
            self.mac_table.remove(&m);
        }

        match self.nexthop_table.remove(addr) {
            Some(_) => info!("remove socket session: {:?}", addr),
            None => {
                debug!("no socket session removed for non-existing socket session: {:?}", addr);
            }
        }
    }

    /// Remove an expired nexthop entry
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use std::time::Duration;
    /// use tokio::runtime::Runtime;
    /// use tokio::time::sleep;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    ///     let nexthop_timeout = 1u64;
    ///     let mut mac_table = ForwardingTable::new(nexthop_timeout, 300);
    ///
    ///     mac_table.update_or_insert_nexthop(&addr);
    ///     assert_eq!(mac_table.nexthop_count() == 1, true);
    ///
    ///     sleep(Duration::from_secs(3)).await;
    ///     mac_table.remove_expired_nexthop();
    ///
    ///     assert_eq!(mac_table.nexthop_count() == 0, true);
    /// });
    /// ```
    pub fn remove_expired_nexthop(&mut self) {
        let mut nexthop_list: Vec<SocketAddr> = Vec::new();
        for (s, t) in self.nexthop_table.iter() {
            if *t < Instant::now() {
                nexthop_list.push(s.clone());
            }
        }
        for s in nexthop_list {
            self.remove_nexthop(&s);
            trace!("remove expired socket session: {:?}", s);
        }
    }

    /// Learning mac address and update mac-table
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use std::time::Duration;
    /// use tokio::runtime::Runtime;
    /// use tokio::time::sleep;
    /// use acton::control::MacAddress;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    ///     let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    ///     let mut mac_table = ForwardingTable::new(30, 300);
    ///
    ///     mac_table.update_or_insert_nexthop(&addr);
    ///     mac_table.mac_learning(&mac, &addr);
    ///
    ///     assert_eq!(mac_table.nexthop_count() == 1, true);
    ///     assert_eq!(mac_table.mac_count() == 1, true);
    ///     assert_eq!(mac_table.get_nexthop(&mac), [addr]);
    /// });
    /// ```
    pub fn mac_learning(&mut self, mac: &MacAddress, nexthop: &SocketAddr) {
        if mac.is_unicast() {
            match self.mac_table.get_mut(&mac.get_value()) {
                Some(nh) => {
                    nh.update_expiry_time(self.mac_aging_timeout);
                }
                None => {
                    if self.mac_table.len() >= MAX_MAC_COUNT {
                        trace!("number of mac entries is overflow. try to remove expired mac entires");
                        self.remove_expired_mac();
                    }
                    if self.mac_table.len() < MAX_MAC_COUNT {
                        trace!("insert a new mac entry: {:?} {:?}", mac, nexthop);
                        self.mac_table.insert(mac.get_value(), NextHop::new(*nexthop, self.mac_aging_timeout));
                    } else {
                        error!("Error: total count of mac entries > MAX_MAC_COUNT")
                    }
                }
            }
        }
    }

    /// Return a sock address by a mac address
    ///
    /// # Argument
    /// * `mac`: mac address value of MacAddress type
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use std::time::Duration;
    /// use tokio::runtime::Runtime;
    /// use tokio::time::sleep;
    /// use acton::control::MacAddress;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    ///     let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    ///
    ///     let mut forwarding_table = ForwardingTable::new(30, 300);
    ///     forwarding_table.mac_learning(&mac, &addr);
    ///
    ///     assert_eq!(forwarding_table.get_nexthop(&mac), [addr]);
    /// });
    /// ```
    pub fn get_nexthop(&self, mac: &MacAddress) -> Vec<SocketAddr> {
        let mut v = Vec::new();

        if mac.is_broadcast() {
            trace!("mac is broadcast mac - flood to all socket sessions");
            for addr in self.nexthop_table.keys() {
                v.push(*addr);
            }
        } else if mac.is_multicast() {
            trace!("mac is muticast mac - flood to all socket sessions");
            for addr in self.nexthop_table.keys() {
                v.push(*addr);
            }
        } else {
            match self.mac_table.get(&mac.get_value()) {
                Some(nexthop) => {
                    let nh = nexthop.get_addr().clone();
                    v.push(nh)
                }
                None => {
                    for addr in self.nexthop_table.keys() {
                        v.push(*addr);
                    }
                }
            }
        }
        v
    }

    /// Learning mac address and update mac-table
    ///
    /// # Example
    /// ```
    /// use std::net::SocketAddr;
    /// use std::time::Duration;
    /// use tokio::runtime::Runtime;
    /// use tokio::time::sleep;
    /// use acton::control::MacAddress;
    /// use acton::control::ForwardingTable;
    ///
    /// Runtime::new().unwrap().block_on(async {
    ///     let nexthop_timeout = 1u64;
    ///     let mac_aging_timeout = 1u64;
    ///     let mut forwarding_table = ForwardingTable::new(1, 1);
    ///
    ///     let mac = MacAddress::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    ///     let addr = "1.1.1.1:8080".parse::<SocketAddr>().unwrap();
    ///     forwarding_table.mac_learning(&mac, &addr);
    ///
    ///     assert_eq!(forwarding_table.mac_count() == 1, true);
    ///     assert_eq!(forwarding_table.get_nexthop(&mac), [addr]);
    ///
    ///     sleep(Duration::from_secs(3)).await;
    ///
    ///     forwarding_table.remove_expired_mac();
    ///
    ///     assert_eq!(forwarding_table.mac_count() == 0, true);
    ///     assert_eq!(forwarding_table.get_nexthop(&mac), []);
    /// });
    /// ```
    pub fn remove_expired_mac(&mut self) {
        let mut mac_list = Vec::new();
        for (mac, nexthop) in self.mac_table.iter() {
            if nexthop.is_expired() {
                mac_list.push(mac.clone());
            }
        }
        for m in mac_list {
            self.mac_table.remove(&m);
            trace!("mac expired: {:?}", m);
        }
    }
}


#[cfg(test)]
mod tests {
    // use super::*;
}
