//! To build and run it:
//!
//! ```bash
//! TS_AUTHKEY=<your-auth-key> cargo run --example echo_server
//! ```
use std::io::{Read, Write};

use libtailscale::Tailscale;

fn main() {
    let mut ts = Tailscale::new();
    ts.set_ephemeral(true).unwrap();
    ts.up().unwrap();

    let mut listener = ts.listen("tcp", ":1999").unwrap();
    loop {
        let mut stream = listener.accept().unwrap();
        let mut buf = [0; 2048];
        while match stream.read(&mut buf) {
            Ok(size) => {
                stream.write_all(&buf[..size]).unwrap();
                true
            }
            Err(_) => {
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                false
            }
        } {}
    }
}
