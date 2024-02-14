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

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::tag,
    combinator::map,
    multi::{length_data, many1, many_till},
    number::complete::{be_u16, be_u8},
    sequence::tuple,
};

const DNS_HDR_SIZE: usize = 12;

#[derive(Debug)]
pub struct DNSHdr<'a> {
    pub id: u16,
    flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub queries: Vec<Query<'a>>,
}

impl<'a> DNSHdr<'a> {
    pub fn new_response(id: u16, queries: Vec<Query<'a>>) -> Self {
        DNSHdr {
            id: id,
            flags: DNSHdr::flags(1, 0, 0, 0, 0, 0, 0),
            qdcount: queries.len() as u16,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            queries: queries,
        }
    }

    pub fn flags(qr: u8, opcode: u8, aa: u8, tc: u8, rd: u8, ra: u8, rcode: u8) -> u16 {
        let flags_h: u8 = (qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd;
        let flags_l: u8 = (ra << 7) | (rcode);

        (flags_h as u16) << 8 | (flags_l as u16)
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf: BytesMut = BytesMut::with_capacity(DNS_HDR_SIZE);

        buf.put_u16(self.id);
        buf.put_u16(self.flags);
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);

        for q in self.queries.iter() {
            q.to_bytes(&mut buf);
        }

        buf.freeze()
    }

    pub fn from_bytes(buf: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rest, (id, flags, qdcount, ancount, nscount, arcount, queries)) = tuple((
            be_u16,
            be_u16,
            be_u16,
            be_u16,
            be_u16,
            be_u16,
            Query::from_bytes,
        ))(buf)?;

        Ok((
            rest,
            DNSHdr {
                id,
                flags,
                qdcount,
                ancount,
                nscount,
                arcount,
                queries,
            },
        ))
    }
}

/*
1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug, Clone)]
pub struct Query<'a> {
    name: Vec<&'a [u8]>,
    pub qtype: u16,
    pub qclass: u16,
}

#[repr(u16)]
#[derive(Debug)]
pub enum RRType {
    A = 1,      // Host Address
    NS = 2,     //an authoritative name server
    MD = 3,     //a mail destination (Obsolete - use MX)
    MF = 4,     //a mail forwarder (Obsolete - use MX)
    CNAME = 5,  //the canonical name for an alias
    SOA = 6,    //marks the start of a zone of authority
    MB = 7,     //a mailbox domain name (EXPERIMENTAL)
    MG = 8,     //a mail group member (EXPERIMENTAL)
    MR = 9,     //a mail rename domain name (EXPERIMENTAL)
    NULL = 10,  // a null RR (EXPERIMENTAL)
    WKS = 11,   // a well known service description
    PTR = 12,   // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15,    // mail exchange
    TXT = 16,   // text strings
}
#[repr(u16)]
#[derive(Debug)]
pub enum RRClass {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
}

impl<'a> Query<'a> {
    pub fn from_bytes(buf: &'a [u8]) -> nom::IResult<&'a [u8], Vec<Self>> {
        let (rest, queries) = many1(map(
            tuple((many_till(length_data(be_u8), tag("\x00")), be_u16, be_u16)),
            |((labels, _), qtype, qclass)| Query {
                name: labels,
                qtype: qtype,
                qclass: qclass,
            },
        ))(buf)?;

        Ok((rest, queries))
    }

    pub fn to_bytes(&self, buf: &mut BytesMut) {
        self.name.iter().for_each(|&l| {
            buf.put_u8(l.len() as u8);
            buf.extend_from_slice(l);
        });
        buf.put_u8(0);
        buf.put_u16(self.qtype);
        buf.put_u16(self.qclass);
    }

    pub fn domain(&self) -> String {
        self.name
            .iter()
            .filter_map(|l| std::str::from_utf8(l).ok())
            .collect::<Vec<_>>()
            .join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding() {
        let answer = DNSHdr::new_response(12345, vec![]);

        assert_eq!(answer.id, 12345);
        assert_eq!(answer.flags & 0x8000, 0x8000);

        let bytes = answer.to_bytes();
        println!("{bytes:?}");
    }

    #[test]
    fn test_query_decode() -> Result<()> {
        let buf = "\x06google\x03com\x00\x00\x01\x00\x01".as_bytes();

        let (_, qs) = Query::from_bytes(buf)?;

        let q = qs.iter().next().unwrap();

        assert_eq!(q.domain(), "google.com");

        assert_eq!(q.qclass, RRClass::IN as u16);
        assert_eq!(q.qtype, RRType::A as u16);

        Ok(())
    }
}
