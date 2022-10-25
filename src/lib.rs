use std::{io, ops::Range};

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

fn calculate_sum(data: &[u8], skip: Option<Range<usize>>) -> u32 {
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

fn calculate_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}
