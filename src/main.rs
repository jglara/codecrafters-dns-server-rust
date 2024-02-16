use anyhow::Result;
use dns_server::DNSServer;
use std::env;

mod dns_hdr;
mod dns_server;

fn main() -> Result<()> {
    let resolver = env::args()
        .zip(env::args().skip(1))
        .find(|(k, _v)| k == "--resolver")
        .map(|(_, v)| v);

    let mut server = DNSServer::new("127.0.0.1:2053", resolver)?;
    server.start();

    Ok(())
}
