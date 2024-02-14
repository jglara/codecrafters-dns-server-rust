use anyhow::Result;

/*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

use bytes::{Buf, BufMut, Bytes, BytesMut};

const DNS_HDR_SIZE: usize = 12;

#[derive(Debug)]
pub struct DNSHdr {
    pub id: u16,
    flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DNSHdr {
    pub fn new_response (id: u16) -> Self {
        DNSHdr {
            id: id,
            flags: DNSHdr::flags(1,0,0,0,0,0,0),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn flags(qr: u8, opcode: u8, aa: u8, tc: u8, rd: u8, ra: u8, rcode: u8) -> u16 {

        let flags_h: u8 = (qr << 7) | (opcode << 3) | (aa<<2) | (tc<<1) | rd;
        let flags_l: u8 = (ra << 7) | (rcode);

        (flags_h as u16) << 8 | (flags_l as u16)


    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf: BytesMut = BytesMut::with_capacity(DNS_HDR_SIZE);

        buf.put_u16_ne(self.id);
        buf.put_u16(self.flags);
        buf.put_u16_ne(self.qdcount);
        buf.put_u16_ne(self.ancount);
        buf.put_u16_ne(self.nscount);
        buf.put_u16_ne(self.arcount);

        buf.freeze()

    }

    pub fn from_bytes(mut buf: &[u8]) -> Result<Self> {
        anyhow::ensure!(buf.len()>=DNS_HDR_SIZE);

        Ok(Self {
            id     : buf.get_u16_ne(),
            flags  : buf.get_u16_ne(),
            qdcount: buf.get_u16_ne(),
            ancount: buf.get_u16_ne(),
            nscount: buf.get_u16_ne(),
            arcount: buf.get_u16_ne(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding() {
        let answer = DNSHdr::new_response(12345);

        assert_eq!(answer.id, 12345);
        assert_eq!(answer.flags &0x8000 , 0x8000);

        let bytes = answer.to_bytes();
        println!("{bytes:?}");
    }

}