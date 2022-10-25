use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
};

pub mod echo;
pub mod echo_test;
pub mod icmp;
pub mod tcp;
pub mod tcp_test;

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

pub fn calculate_sum(data: &[u8], skip: Option<Range<usize>>) -> u32 {
    let mut sum = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        if let Some(skip) = &skip {
            if skip.contains(&i) {
                continue;
            }
        }
        match i % 2 {
            0 => {
                sum += u32::from(byte) << 8;
            }
            _ => {
                sum += u32::from(byte);
            }
        }
    }
    sum
}

pub fn calculate_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

pub fn get_eth_src_ipv4() -> io::Result<Ipv4Addr> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let dst_addr = SocketAddr::new("8.8.8.8".parse().unwrap(), 80);
    socket.connect(&dst_addr.into())?;
    let src_addr = socket.local_addr()?;
    match src_addr.as_socket_ipv4() {
        Some(src_addr) => Ok(*src_addr.ip()),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an ipv4 address",
        )),
    }
}

pub fn get_eth_src_ipv6() -> io::Result<Ipv6Addr> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    let dst_addr = SocketAddr::new("2001:4860:4860::8888".parse().unwrap(), 80);
    socket.connect(&dst_addr.into())?;
    let src_addr = socket.local_addr()?;
    match src_addr.as_socket_ipv6() {
        Some(src_addr) => Ok(*src_addr.ip()),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an ipv6 address",
        )),
    }
}
