use anyhow::Result;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, UdpSocket},
};
mod dns_hdr;

use dns_hdr::{Answer, DNSHdr, RRClass, RRType};

use crate::dns_hdr::{Flags, RCode};

fn main() -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    let rr_db: HashMap<String, (u32, [u8; 4])> = HashMap::from([(
        "codecrafters.io".to_string(),
        (60, Ipv4Addr::new(192, 168, 10, 10).octets()),
    )]);

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {} {:?}", size, source, &buf[..size]);
                if let Ok((_, request)) = DNSHdr::from_bytes(&buf[..size]) {
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
                            let answs = rr_db.get(&domain).map(|(ttl, data)| {
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
                        _ => {
                            DNSHdr::new(
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
                            .to_bytes()
                        },
                    };

                    udp_socket
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

    Ok(())
}
