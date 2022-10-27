use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

pub fn ipv4_payload(pkt: &[u8]) -> io::Result<&[u8]> {
    if pkt.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet too short",
        ));
    }
    let hdr_len = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < hdr_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet too short",
        ));
    }
    Ok(&pkt[hdr_len..])
}

/// ```text
/// 0               1               2               3               4
/// +---------------------------------------------------------------+
/// |                         Source Address                        |
/// +---------------------------------------------------------------+
/// |                      Destination Address                      |
/// +---------------------------------------------------------------+
/// |     Zero      |   Protocol    |          TCP Length           |
/// +---------------------------------------------------------------+
/// ```
pub struct PseudoIpv4Header<'a> {
    pub ipv4_info: &'a Ipv4PeerIps,
    pub protocol: u8,
    pub length: u16,
}

impl<'a> PseudoIpv4Header<'a> {
    pub fn calculate_sum(&self) -> u32 {
        let mut sum = 0u32;

        let src_addr = self.ipv4_info.src_ip.octets();
        let dst_addr = self.ipv4_info.dst_ip.octets();

        sum += u16::from_be_bytes([src_addr[0], src_addr[1]]) as u32;
        sum += u16::from_be_bytes([src_addr[2], src_addr[3]]) as u32;
        sum += u16::from_be_bytes([dst_addr[0], dst_addr[1]]) as u32;
        sum += u16::from_be_bytes([dst_addr[2], dst_addr[3]]) as u32;
        sum += self.protocol as u32;
        sum += self.length as u32;

        sum
    }
}

pub struct Ipv4PeerIps {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

/// Pseudo header for IPv6
/// ```text
/// 0               1               2               3               4
/// +---------------------------------------------------------------+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                         Source Address                        +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                      Destination Address                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                   TCP Length (upper 16 bits)                  |
/// +---------------------------------------------------------------+
/// |                   TCP Length (lower 16 bits)                  |
/// +---------------------------------------------------------------+
/// |                   Zero (upper 16 bits)                        |
/// +---------------------------------------------------------------+
/// |                   Zero (lower 16 bits)                        |
/// +---------------------------------------------------------------+
/// |                   Next Header (upper 16 bits)                 |
/// +---------------------------------------------------------------+
/// |                   Next Header (lower 16 bits)                 |
/// +---------------------------------------------------------------+
/// ```
pub struct PseudoIpv6Header<'a> {
    pub ipv6_info: &'a Ipv6PeerIps,
    pub protocol: u8,
    pub length: u32,
}

impl<'a> PseudoIpv6Header<'a> {
    pub fn calculate_sum(&self) -> u32 {
        let mut sum = 0u32;

        let src_addr = self.ipv6_info.src_ip.octets();
        let dst_addr = self.ipv6_info.dst_ip.octets();

        sum += u16::from_be_bytes([src_addr[0], src_addr[1]]) as u32;
        sum += u16::from_be_bytes([src_addr[2], src_addr[3]]) as u32;
        sum += u16::from_be_bytes([src_addr[4], src_addr[5]]) as u32;
        sum += u16::from_be_bytes([src_addr[6], src_addr[7]]) as u32;
        sum += u16::from_be_bytes([src_addr[8], src_addr[9]]) as u32;
        sum += u16::from_be_bytes([src_addr[10], src_addr[11]]) as u32;
        sum += u16::from_be_bytes([src_addr[12], src_addr[13]]) as u32;
        sum += u16::from_be_bytes([src_addr[14], src_addr[15]]) as u32;

        sum += u16::from_be_bytes([dst_addr[0], dst_addr[1]]) as u32;
        sum += u16::from_be_bytes([dst_addr[2], dst_addr[3]]) as u32;
        sum += u16::from_be_bytes([dst_addr[4], dst_addr[5]]) as u32;
        sum += u16::from_be_bytes([dst_addr[6], dst_addr[7]]) as u32;
        sum += u16::from_be_bytes([dst_addr[8], dst_addr[9]]) as u32;
        sum += u16::from_be_bytes([dst_addr[10], dst_addr[11]]) as u32;
        sum += u16::from_be_bytes([dst_addr[12], dst_addr[13]]) as u32;
        sum += u16::from_be_bytes([dst_addr[14], dst_addr[15]]) as u32;

        sum += self.length;
        sum += self.protocol as u32;

        sum
    }
}

pub struct Ipv6PeerIps {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

pub enum PeerIps {
    Ipv4(Ipv4PeerIps),
    Ipv6(Ipv6PeerIps),
}
