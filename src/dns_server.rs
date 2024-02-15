use crate::dns_hdr::{Answer, DNSHdr, Flags, RCode, RRClass, RRType};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};

pub struct DNSServer {
    socket: UdpSocket,
    rr_db: HashMap<String, (u32, [u8; 4])>,
}

impl DNSServer {
    pub fn new(addr: &str) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).context("Failed to bind to address")?;

        Ok(Self {
            socket: udp_socket,
            rr_db: HashMap::from([(
                "codecrafters.io".to_string(),
                (60, Ipv4Addr::new(192, 168, 10, 10).octets()),
            ),
            (
                "stackoverflow.com".to_string(),
                (60, Ipv4Addr::new(192, 168, 10, 20).octets()),
            )]),
        })
    }

    pub fn start(&mut self) {
        let mut buf = [0; 512];

        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((size, source)) => {
                    println!("Received {} bytes from {} {:?}", size, source, &buf[..size]);
                    let req = DNSHdr::decompress_names(&buf[..size]).unwrap();
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
                                let domain = request.queries[0].domain();
                                let answs = self
                                    .rr_db
                                    .get("codecrafters.io")
                                    .map(|(ttl, data)| {
                                        Answer::new(&domain, RRType::A, RRClass::IN, *ttl, data)
                                    });

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
                                    Vec::from_iter(answs.into_iter()),
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
