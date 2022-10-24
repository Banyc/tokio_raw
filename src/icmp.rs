use std::io;

use crate::{calculate_checksum, calculate_sum};

#[derive(Debug)]
pub enum IcmpVersion {
    V4,
    V6,
}

#[derive(Debug)]
pub enum IcmpKind<'buf> {
    EchoRequest(IcmpEcho<'buf>),
    EchoReply(IcmpEcho<'buf>),
    Other { ty: u8, code: u8, data: &'buf [u8] },
}

impl<'buf> IcmpKind<'buf> {
    pub fn encode(&self, buf: &mut [u8], version: IcmpVersion) -> io::Result<usize> {
        if buf.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }
        let pkt = match self {
            IcmpKind::EchoRequest(echo) => {
                match version {
                    IcmpVersion::V4 => {
                        buf[0] = 8;
                    }
                    IcmpVersion::V6 => {
                        buf[0] = 128;
                    }
                } // type
                buf[1] = 0; // code
                buf[2..4].copy_from_slice(&(0u16).to_be_bytes()); // checksum
                let data_len = echo.encode(&mut buf[4..]);
                &buf[..4 + data_len]
            }
            IcmpKind::EchoReply(echo) => {
                match version {
                    IcmpVersion::V4 => {
                        buf[0] = 0;
                    }
                    IcmpVersion::V6 => {
                        buf[0] = 129;
                    }
                } // type
                buf[1] = 0; // code
                buf[2..4].copy_from_slice(&(0u16).to_be_bytes()); // checksum
                let data_len = echo.encode(&mut buf[4..]);
                &buf[..4 + data_len]
            }
            IcmpKind::Other { ty, code, data } => {
                buf[0] = *ty;
                buf[1] = *code;
                buf[2..4].copy_from_slice(&(0u16).to_be_bytes()); // checksum
                buf[4..4 + data.len()].copy_from_slice(data);
                &buf[..4 + data.len()]
            }
        };
        let pkt_len = pkt.len();
        if let IcmpVersion::V4 = version {
            let sum = calculate_sum(pkt, None);
            let checksum = calculate_checksum(sum);
            buf[2..4].copy_from_slice(&checksum.to_be_bytes());
        } // IPv6: checksum is calculated by the kernel
        Ok(pkt_len)
    }

    pub fn decode(pkt: &'buf [u8], version: IcmpVersion) -> io::Result<Self> {
        if pkt.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too small",
            ));
        }
        let ty = pkt[0];
        let code = pkt[1];
        // kernel should have already validated checksum
        // let checksum = u16::from_be_bytes([pkt[2], pkt[3]]);
        // if let ICMPVersion::V4 = version {
        //     let sum = calculate_sum(pkt, Some(2..4));
        //     let calculated_checksum = calculate_checksum(sum);
        //     if checksum != calculated_checksum {
        //         return Err(io::Error::new(
        //             io::ErrorKind::InvalidData,
        //             "invalid checksum",
        //         ));
        //     }
        // } // checksums of ICMP v6 involve IPv6 pseudo-header (https://www.rfc-editor.org/rfc/rfc2460#section-8.1)
        let data = &pkt[4..];
        match (version, ty, code) {
            (IcmpVersion::V4, 8, 0) | (IcmpVersion::V6, 128, 0) => {
                Ok(IcmpKind::EchoRequest(IcmpEcho::decode(data)?))
            }
            (IcmpVersion::V4, 0, 0) | (IcmpVersion::V6, 129, 0) => {
                Ok(IcmpKind::EchoReply(IcmpEcho::decode(data)?))
            }
            _ => Ok(IcmpKind::Other { ty, code, data }),
        }
    }
}

#[derive(Debug)]
pub struct IcmpEcho<'buf> {
    pub identifier: u16,
    pub seq: u16,
    pub data: &'buf [u8],
}

impl<'buf> IcmpEcho<'buf> {
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0..2].copy_from_slice(&self.identifier.to_be_bytes());
        buf[2..4].copy_from_slice(&self.seq.to_be_bytes());
        buf[4..4 + self.data.len()].copy_from_slice(self.data);
        4 + self.data.len()
    }

    pub fn decode(pkt: &'buf [u8]) -> io::Result<Self> {
        if pkt.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too small",
            ));
        }
        let identifier = u16::from_be_bytes([pkt[0], pkt[1]]);
        let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
        let data = &pkt[4..];
        Ok(IcmpEcho {
            identifier,
            seq,
            data,
        })
    }
}
