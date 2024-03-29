use std::io;

use crate::{
    calculate_checksum, calculate_sum,
    ip::{PeerIps, PseudoIpv4Header, PseudoIpv6Header},
};

/// ```text
/// 0               1               2               3               4
/// +---------------------------------------------------------------+
/// |          Source Port          |       Destination Port        |
/// +---------------------------------------------------------------+
/// |                        Sequence Number                        |
/// +---------------------------------------------------------------+
/// |                    Acknowledgment Number                      |
/// +---------------------------------------------------------------+
/// |  Data |           |U|A|P|R|S|F|                               |
/// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
/// |       |           |G|K|H|T|N|N|                               |
/// +---------------------------------------------------------------+
/// |           Checksum            |         Urgent Pointer        |
/// +---------------------------------------------------------------+
/// |                    Options                    |    Padding    |
/// +---------------------------------------------------------------+
/// |                             data                              |
/// +---------------------------------------------------------------+
/// ```
pub struct Tcp<'buf> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,

    // flags
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,

    pub window_size: u16,
    pub urgent_ptr: u16,
    pub options: &'buf [u8],
    pub data: &'buf [u8],
}

impl<'buf> Tcp<'buf> {
    pub fn encode(&self, buf: &mut [u8], ip: &PeerIps) -> io::Result<usize> {
        let data_offset = 5 + self.options.len() / 4;
        if data_offset > 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data offset too large",
            ));
        }
        if buf.len() < data_offset * 4 + self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }
        buf[0..2].copy_from_slice(&(self.src_port).to_be_bytes());
        buf[2..4].copy_from_slice(&(self.dst_port).to_be_bytes());
        buf[4..8].copy_from_slice(&(self.seq_num).to_be_bytes());
        buf[8..12].copy_from_slice(&(self.ack_num).to_be_bytes());

        buf[12] = (data_offset << 4) as u8;

        // flags
        buf[13] = if self.urg { 0b0010_0000 } else { 0 }
            | if self.ack { 0b0001_0000 } else { 0 }
            | if self.psh { 0b0000_1000 } else { 0 }
            | if self.rst { 0b0000_0100 } else { 0 }
            | if self.syn { 0b0000_0010 } else { 0 }
            | if self.fin { 0b0000_0001 } else { 0 };

        buf[14..16].copy_from_slice(&(self.window_size).to_be_bytes());
        buf[16..18].copy_from_slice(&(0u16).to_be_bytes()); // checksum
        buf[18..20].copy_from_slice(&(self.urgent_ptr).to_be_bytes());

        // options
        buf[20..20 + self.options.len()].copy_from_slice(self.options);

        // padding
        (20 + self.options.len()..data_offset * 4).for_each(|i| {
            buf[i] = 0;
        });

        // data
        buf[data_offset * 4..data_offset * 4 + self.data.len()].copy_from_slice(self.data);

        // pkt
        let pkt = &mut buf[..data_offset * 4 + self.data.len()];

        // checksum
        match &ip {
            PeerIps::Ipv4(ip) => {
                let ip_header = PseudoIpv4Header {
                    ipv4_info: ip,
                    protocol: 6,
                    length: pkt.len() as u16,
                };
                let sum = ip_header.calculate_sum() + calculate_sum(pkt, None);
                let checksum = calculate_checksum(sum);
                pkt[16..18].copy_from_slice(&(checksum).to_be_bytes());
            }
            PeerIps::Ipv6(ip) => {
                let ip_header = PseudoIpv6Header {
                    ipv6_info: ip,
                    protocol: 6,
                    length: pkt.len() as u32,
                };
                let sum = ip_header.calculate_sum() + calculate_sum(pkt, None);
                let checksum = calculate_checksum(sum);
                pkt[16..18].copy_from_slice(&(checksum).to_be_bytes());
            }
        }

        Ok(pkt.len())
    }

    pub fn decode(buf: &'buf [u8]) -> io::Result<Tcp<'buf>> {
        if buf.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }
        let data_offset = (buf[12] >> 4) as usize;
        if buf.len() < data_offset * 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }
        let options = &buf[20..data_offset * 4];
        let data = &buf[data_offset * 4..];

        Ok(Tcp {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            seq_num: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ack_num: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),

            urg: buf[13] & 0b0010_0000 != 0,
            ack: buf[13] & 0b0001_0000 != 0,
            psh: buf[13] & 0b0000_1000 != 0,
            rst: buf[13] & 0b0000_0100 != 0,
            syn: buf[13] & 0b0000_0010 != 0,
            fin: buf[13] & 0b0000_0001 != 0,

            window_size: u16::from_be_bytes([buf[14], buf[15]]),
            urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
            options,
            data,
        })
    }
}
