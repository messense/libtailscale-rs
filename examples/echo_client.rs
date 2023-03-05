//! To build and run it:
//!
//! ```bash
//! TS_AUTHKEY=<your-auth-key> cargo run --example echo_client
//! ```
use std::env;
use std::io::{Read, Write};

use libtailscale::Tailscale;

fn main() {
    let mut args = env::args().skip(1);
    let Some(addr) = args.next() else {
        eprintln!("USAGE: echo_client <addr>");
        std::process::exit(1);
    };

    let mut ts = Tailscale::new();
    ts.set_ephemeral(true).unwrap();
    ts.set_logfd(-1).unwrap();
    ts.up().unwrap();
    let mut stream = ts.dial("tcp", &addr).unwrap();

    println!("Connected to {}", addr);

    loop {
        let mut buf = String::new();
        let size = std::io::stdin().read_line(&mut buf).unwrap();
        stream.write_all(&buf.as_bytes()[..size]).unwrap();

        let mut data = vec![0; buf.len()];
        match stream.read_exact(&mut data) {
            Ok(_) => {
                print!("{}", String::from_utf8(data).unwrap());
            }
            Err(e) => {
                println!("Failed to receive data: {}", e);
            }
        }
    }
}
