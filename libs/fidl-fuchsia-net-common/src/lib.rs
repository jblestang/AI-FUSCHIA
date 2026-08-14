// Minimal stub of Fuchsia fuchsia.net FIDL types for standalone cargo builds.

#![allow(missing_docs)]

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Address { pub addr: [u8; 4] }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Address { pub addr: [u8; 16] }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpAddress { Ipv4(Ipv4Address), Ipv6(Ipv6Address) }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Subnet { pub addr: IpAddress, pub prefix_len: u8 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4AddressWithPrefix { pub addr: Ipv4Address, pub prefix_len: u8 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv6AddressWithPrefix { pub addr: Ipv6Address, pub prefix_len: u8 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MacAddress { pub octets: [u8; 6] }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4SocketAddress { pub address: Ipv4Address, pub port: u16 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv6SocketAddress { pub address: Ipv6Address, pub port: u16, pub zone_index: u64 }
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SocketAddress { Ipv4(Ipv4SocketAddress), Ipv6(Ipv6SocketAddress) }
