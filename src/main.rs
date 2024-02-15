use anyhow::Result;
use dns_server::DNSServer;

mod dns_hdr;
mod dns_server;




fn main() -> Result<()> {

    let mut server = DNSServer::new("127.0.0.1:2053")?;
    server.start();
    
    Ok(())
}
