use anyhow::Result;
use std::net::UdpSocket;
mod dns_hdr;

use dns_hdr::DNSHdr;

fn main() -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0;512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                if let Ok(request) = DNSHdr::from_bytes(&buf) {
                    eprintln!("Received DNS query: {request:?}");
                    let response = DNSHdr::new_response(request.id);

                    udp_socket
                        .send_to(&response.to_bytes(), source)
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
