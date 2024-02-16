use crate::dns_hdr::{Answer, DNSHdr, Flags, OpCode, Query, RCode, RRClass, RRType};
use anyhow::{Context, Result};
use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};

struct Resolver {
    socket: UdpSocket,
}

impl Resolver {
    fn new(addr: &str) -> Result<Self> {
        let udp_socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind to address")?;
        udp_socket.connect(addr)?;

        Ok(Self { socket: udp_socket })
    }

    fn resolve_a(&mut self, domain: Vec<&[u8]>) -> Result<(u32, Ipv4Addr)> {
        let mut rng = rand::thread_rng();

        // create a dns request
        let id = rng.gen();
        let flags = Flags {
            qr: 0,
            opcode: OpCode::QUERY as u8,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            rcode: 0,
        };
        let query = Query {
            name: domain,
            qtype: RRType::A as u16,
            qclass: RRClass::IN as u16,
        };
        let req = DNSHdr::new(id, flags, vec![query], vec![]);
        eprintln!("Sending {req:?}");

        // send to resolver
        self.socket.send(&req.to_bytes())?;

        // wait for response and parse addr
        let mut buf = [0; 512];

        let (size, source) = self.socket.recv_from(&mut buf)?;

        println!("Received {} bytes from {} {:?}", size, source, &buf[..size]);
        let answer = &buf[..size];
        if let Ok((_, answer)) = DNSHdr::from_bytes(&answer) {
            eprintln!(
                "Received DNS answer: {} {} {:?} ", answer.queries.len(), answer.answers.len(),
                answer
                    .answers
                    .iter()
                    .map(|a| format!(
                        "{:?} ttl={} qclass={} qtype={}",
                        a.rddata, a.ttl, a.qclass, a.qtype
                    ))
                    .collect::<Vec<_>>()
            );

            let rddata = answer.answers[0].rddata;
            let ttl = answer.answers[0].ttl;
            let ip = Ipv4Addr::new(rddata[0], rddata[1], rddata[2], rddata[3]);

            Ok((ttl, ip))
        } else {
            anyhow::bail!("Resolver failed")
        }
    }
}

pub struct DNSServer {
    socket: UdpSocket,
    rr_db: HashMap<String, (u32, [u8; 4])>,
    resolver: Option<Resolver>,
}

impl DNSServer {
    pub fn new(addr: &str, resolver: Option<String>) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).context("Failed to bind to address")?;

        Ok(Self {
            socket: udp_socket,
            rr_db: HashMap::from([
                (
                    "codecrafters.io".to_string(),
                    (60, Ipv4Addr::new(192, 168, 10, 10).octets()),
                ),
                (
                    "stackoverflow.com".to_string(),
                    (60, Ipv4Addr::new(192, 168, 10, 20).octets()),
                ),
            ]),
            resolver: resolver.map(|addr| Resolver::new(&addr).expect(&format!("invalid {addr:?}"))),
        })
    }

    pub fn start(&mut self) {
        let mut buf = [0; 512];

        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((size, source)) => {
                    println!("Received {} bytes from {} {:?}", size, source, &buf[..size]);
                    let req = &buf[..size];
                    if let Ok((_, request)) = DNSHdr::from_bytes(&req) {
                        eprintln!(
                            "Received DNS query: {:?} ",
                            request
                                .queries
                                .iter()
                                .map(|q| format!("{} {} {}", q.domain(), q.qclass, q.qtype))
                                .collect::<Vec<_>>()
                        );

                        let response = match request.flags.opcode {
                            0 => {
                                let answs = match &mut self.resolver {
                                    None => request
                                        .queries
                                        .iter()
                                        .filter_map(|q| {
                                            self.rr_db.get("codecrafters.io").map(|(ttl, data)| {
                                                Answer::new(
                                                    q.name.clone(),
                                                    RRType::A,
                                                    RRClass::IN,
                                                    *ttl,
                                                    data,
                                                )
                                            })
                                        })
                                        .collect::<Vec<_>>(),
                                    Some(resolver) => {
                                        
                                        let ans = request
                                            .queries
                                            .iter()
                                            .filter(|q| !self.rr_db.contains_key(&q.domain()))
                                            .map(|q| (q, resolver.resolve_a(q.name.clone()).map(|(ttl, ip)| (ttl, ip.octets())).unwrap()))
                                            .collect::<Vec<_>>();

                                        self.rr_db.extend(ans.iter().map(|(q, (ttl, ip))| (q.domain(), (*ttl, *ip))));

                                        request
                                        .queries
                                        .iter()
                                        .filter_map(|q| {
                                            self.rr_db.get(&q.domain()).map(|(ttl, data)| {
                                                Answer::new(
                                                    q.name.clone(),
                                                    RRType::A,
                                                    RRClass::IN,
                                                    *ttl,
                                                    data,
                                                )
                                            })
                                        })
                                        .collect::<Vec<_>>()

                                        
                                    }
                                };

                                DNSHdr::new(
                                    request.id,
                                    Flags {
                                        qr: 1,
                                        aa: 0,
                                        tc: 0,
                                        ra: 0,
                                        rcode: RCode::OK as u8,
                                        ..request.flags
                                    },
                                    request.queries.clone(),
                                    answs,
                                )
                                .to_bytes()
                            }
                            _ => DNSHdr::new(
                                request.id,
                                Flags {
                                    qr: 1,
                                    aa: 0,
                                    tc: 0,
                                    ra: 0,
                                    rcode: RCode::NotImplemted as u8,
                                    ..request.flags
                                },
                                request.queries.clone(),
                                vec![],
                            )
                            .to_bytes(),
                        };

                        self.socket
                            .send_to(&response, source)
                            .expect("Failed to send response");
                    };
                }
                Err(e) => {
                    eprintln!("Error receiving data: {}", e);
                    break;
                }
            }
        }
    }
}
