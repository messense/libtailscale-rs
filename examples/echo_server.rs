//! To build and run it:
//!
//! ```bash
//! TS_AUTHKEY=<your-auth-key> cargo run --example echo_server
//! ```
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;

use libtailscale::Tailscale;

fn handle_client(mut stream: TcpStream) {
    let mut buf = [0; 2048];
    while match stream.read(&mut buf) {
        Ok(0) => false, // connection closed
        Ok(size) => {
            stream.write_all(&buf[..size]).unwrap();
            true
        }
        Err(_) => {
            let _ret = stream.shutdown(std::net::Shutdown::Both);
            false
        }
    } {}
}

fn main() {
    let mut ts = Tailscale::new();
    ts.set_ephemeral(true).unwrap();
    ts.up().unwrap();

    let listener = ts.listen("tcp", ":1999").unwrap();
    loop {
        let stream = listener.accept().unwrap();
        thread::spawn(move || {
            handle_client(stream);
        });
    }
}
