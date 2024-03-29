#[allow(unused_imports)]
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
    combinator::{map, verify},
    multi::{length_data, many_m_n},
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
};

use nom::bits::complete::take;

const DNS_HDR_SIZE: usize = 12;

#[derive(Debug, Copy, Clone)]
pub struct Flags {
    pub qr: u8,
    pub opcode: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub rcode: u8,
}

impl Flags {
    pub fn compress_u16(&self) -> u16 {
        let flags_h: u8 =
            (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        let flags_l: u8 = (self.ra << 7) | (self.rcode);

        (flags_h as u16) << 8 | (flags_l as u16)
    }

    fn parse_flags<'a>(input: (&'a [u8], usize)) -> nom::IResult<(&'a [u8], usize), Flags> {
        map(
            tuple((
                take(1u8),
                take(4u8),
                take(1u8),
                take(1u8),
                take(1u8),
                take(1u8),
                take(3u8),
                take(4u8),
            )),
            |(qr, opcode, aa, tc, rd, ra, _, rcode): (u8, u8, u8, u8, u8, u8, u8, u8)| Flags {
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                rcode,
            },
        )(input)
    }
}

#[repr(u8)]
#[allow(dead_code)]
pub enum OpCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
}

#[repr(u8)]
#[allow(dead_code)]
pub enum RCode {
    OK = 0,
    FmtError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemted = 4,
    Refused = 5,
}

#[derive(Debug)]
pub struct DNSHdr<'a> {
    pub id: u16,
    pub flags: Flags,
    pub nscount: u16,
    pub arcount: u16,
    pub queries: Vec<Query<'a>>,
    pub answers: Vec<Answer<'a>>,
}

impl<'a> DNSHdr<'a> {
    pub fn new(id: u16, flags: Flags, queries: Vec<Query<'a>>, answers: Vec<Answer<'a>>) -> Self {
        DNSHdr {
            id: id,
            flags: flags,
            nscount: 0,
            arcount: 0,
            queries: queries,
            answers: answers,
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf: BytesMut = BytesMut::with_capacity(DNS_HDR_SIZE);

        buf.put_u16(self.id);
        buf.put_u16(self.flags.compress_u16());
        buf.put_u16(self.queries.len() as u16);
        buf.put_u16(self.answers.len() as u16);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);

        for q in self.queries.iter() {
            q.to_bytes(&mut buf);
        }

        for a in self.answers.iter() {
            a.to_bytes(&mut buf);
        }

        buf.freeze()
    }


    pub fn from_bytes(buf: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rest, (id, flags, qdcount, ancount, nscount, arcount)) = tuple((
            be_u16,
            nom::bits::bits(Flags::parse_flags),
            be_u16,
            be_u16,
            be_u16,
            be_u16,
        ))(buf)?;

        let (rest, queries) = Query::from_bytes(rest, qdcount as usize, buf)?;
        let (rest, answers) = Answer::from_bytes(rest, ancount as usize, buf)?;

        Ok((
            rest,
            DNSHdr {
                id,
                flags,
                nscount,
                arcount,
                queries,
                answers,
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
    pub name: Vec<&'a [u8]>,
    pub qtype: u16,
    pub qclass: u16,
}

#[repr(u16)]
#[derive(Debug)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub enum RRClass {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
}

fn parse_labels<'a>(buf: &'a [u8], pkt: &'a [u8]) -> nom::IResult<&'a [u8], Vec<&'a [u8]>> {
    let mut labels = vec![];
    let mut rest = buf;

    loop {
        if let Ok((r, label)) =
            length_data(verify(be_u8::<_, nom::error::Error<_>>, |&l| l < 127))(rest)
        {
            rest = r;
            if label.len() > 0 {
                labels.push(label);
            } else {
                break;
            }
        } else {
            let (r, offset) = be_u16(rest)?;
            let offset = (offset & 0b0011_1111_1111_1111) as usize;
            if offset < pkt.len() {
                let (_, compress_labels) = parse_labels(&pkt[offset..], pkt)?;
                labels.extend(compress_labels);

                rest = r;
                break;
            }
        }
    }

    Ok((rest, labels))
}


impl<'a> Query<'a> {
    pub fn from_bytes(buf: &'a [u8], n: usize, pkt: &'a [u8]) -> nom::IResult<&'a [u8], Vec<Self>> {
        let (rest, queries) = many_m_n(
            n,
            n,
            map(
                tuple((|i| parse_labels(i, pkt), be_u16, be_u16)),
                |(labels, qtype, qclass)| Query {
                    name: labels,
                    qtype: qtype,
                    qclass: qclass,
                },
            ),
        )(buf)?;

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

/*
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug, Clone)]
pub struct Answer<'a> {
    pub name: Vec<&'a [u8]>,
    pub qtype: u16,
    pub qclass: u16,
    pub ttl: u32,
    pub rddata: &'a [u8],
}

impl<'a> Answer<'a> {
    pub fn new(
        name: Vec<&'a [u8]>,
        qtype: RRType,
        qclass: RRClass,
        ttl: u32,
        data: &'a [u8],
    ) -> Self {
        

        Answer {
            name,
            qtype: qtype as u16,
            qclass: qclass as u16,
            ttl,
            rddata: data,
        }
    }

    pub fn from_bytes(buf: &'a [u8], n: usize, pkt:&'a [u8]) -> nom::IResult<&'a [u8], Vec<Self>> {
        let (rest, responses) = many_m_n(
            n,
            n,
            map(
                tuple((
                    |i| {parse_labels(i, pkt)},
                    be_u16,
                    be_u16,
                    be_u32,
                    length_data(be_u16),
                )),
                |(labels, qtype, qclass, ttl, rddata)| Answer {
                    name: labels,
                    qtype: qtype,
                    qclass: qclass,
                    ttl: ttl,
                    rddata,
                },
            ),
        )(buf)?;

        Ok((rest, responses))
    }

    pub fn to_bytes(&self, buf: &mut BytesMut) {
        self.name.iter().for_each(|&l| {
            buf.put_u8(l.len() as u8);
            buf.extend_from_slice(l);
        });
        buf.put_u8(0);
        buf.put_u16(self.qtype);
        buf.put_u16(self.qclass);
        buf.put_u32(self.ttl);
        buf.put_u16(self.rddata.len() as u16);
        buf.extend(self.rddata);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv4Addr};

    use super::*;

    #[test]
    fn test_encoding() {
        let flags = Flags {
            qr: 1,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            rcode: 0,
        };
        let answer = DNSHdr::new(12345, flags, vec![], vec![]);

        assert_eq!(answer.id, 12345);
        assert_eq!(answer.flags.qr, 1);

        let bytes = answer.to_bytes();
        println!("{bytes:?}");
    }

    #[test]
    fn test_query_decode() -> Result<()> {
        let buf: &[u8] = &[
            250, 252, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102, 116,
            101, 114, 115, 3, 105, 111, 120, 0, 0, 1, 0, 1,
        ];

        println!("{buf:?}");

        let (_, qs) = Query::from_bytes(&buf[DNS_HDR_SIZE..], 1, &buf).unwrap();

        let q = qs.iter().next().unwrap();

        //assert_eq!(q.domain(), "google.com");

        assert_eq!(q.qclass, RRClass::IN as u16);
        assert_eq!(q.qtype, RRType::A as u16);

        Ok(())
    }

    #[test]
    fn test_query_decode_compressed() -> Result<()> {
        //let buf: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,103,111,111,103,108,101,0x03,99,111,109,0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x01, 0x00, 0x01];
        let buf = &[
            212, 158, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 97, 98, 99, 17, 108, 111, 110, 103, 97, 115,
            115, 100, 111, 109, 97, 105, 110, 110, 97, 109, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3,
            100, 101, 102, 192, 16, 0, 1, 0, 1,
        ];

        //let buf = DNSHdr::decompress_names(buf)?;
        //println!("{buf:?}");

        let (_, qs) = Query::from_bytes(&buf[DNS_HDR_SIZE..], 2, buf).unwrap();

        let q = qs.iter().skip(1).next().unwrap();
        println!("{q:?}");

        //assert_eq!(q.domain(), "google.com");

        assert_eq!(q.qclass, RRClass::IN as u16);
        assert_eq!(q.qtype, RRType::A as u16);

        Ok(())
    }

    #[test]
    fn test_answer_encode() -> Result<()> {
        let rr_db: HashMap<String, (u32, Ipv4Addr)> = HashMap::from([(
            "google.com".to_string(),
            (60, Ipv4Addr::new(192, 168, 10, 10)),
        )]);
        let domain = "google.com";

        let (ttl, data) = rr_db[domain];
        let data = data.octets();

        let answer = Answer::new(
            vec![&[0x03, 10, 20, 30, 0x0]],
            RRType::A,
            RRClass::IN,
            ttl,
            &data,
        );
        let mut buf = BytesMut::new();
        answer.to_bytes(&mut buf);

        println!("{answer:?} -> {buf:?}");

        Ok(())
    }
}
