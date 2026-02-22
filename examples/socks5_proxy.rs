//! SOCKS5 proxy server that routes traffic through a Tailscale exit node.
//!
//! This creates an independent userspace Tailscale node, configures it to use
//! a specified exit node, then runs a local SOCKS5 proxy. All traffic through
//! the proxy is routed via the exit node. The system Tailscale is unaffected.
//!
//! # Usage
//!
//! ```bash
//! TS_AUTHKEY=<your-auth-key> cargo run --example socks5_proxy -- \
//!     --exit-node <exit-node-ip-or-name> \
//!     --listen 127.0.0.1:1080
//! ```
//!
//! Then configure your application to use the SOCKS5 proxy:
//!
//! ```bash
//! curl --proxy socks5h://127.0.0.1:1080 https://ifconfig.me
//! ```

use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process;
use std::sync::Arc;
use std::thread;

use libtailscale::Tailscale;

fn main() {
    let args = parse_args();

    eprintln!("[info] Starting tailscale node...");
    let mut ts = Tailscale::new();
    ts.set_ephemeral(true).unwrap();
    if let Some(ref hostname) = args.hostname {
        ts.set_hostname(hostname).unwrap();
    }
    // Disable logging by default (fd = -1)
    ts.set_logfd(-1).unwrap();
    ts.up().unwrap();

    let ips = ts.get_ips().unwrap();
    eprintln!("[info] Tailscale is up, IPs: {:?}", ips);

    // Configure exit node via LocalAPI
    let loopback = ts.loopback().unwrap();
    eprintln!("[info] LocalAPI at {}", loopback.address);

    set_exit_node(&loopback, &args.exit_node, args.allow_lan);
    eprintln!("[info] Exit node set to: {}", args.exit_node);

    let ts = Arc::new(ts);

    // Start SOCKS5 proxy on local address
    let listener = TcpListener::bind(&args.listen).unwrap_or_else(|e| {
        eprintln!("[fatal] Failed to bind {}: {}", args.listen, e);
        process::exit(1);
    });
    eprintln!("[info] SOCKS5 proxy listening on socks5://{}", args.listen);

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let ts = Arc::clone(&ts);
                thread::spawn(move || {
                    if let Err(e) = handle_socks5(client, &ts) {
                        eprintln!("[error] {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[error] Accept failed: {}", e),
        }
    }
}

// -- SOCKS5 implementation (no-auth, CONNECT only) --

fn handle_socks5(mut client: TcpStream, ts: &Tailscale) -> io::Result<()> {
    // 1. Greeting
    let mut buf = [0u8; 258];
    client.read_exact(&mut buf[..2])?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods])?;

    // We only support no-auth (0x00)
    if !buf[..nmethods].contains(&0x00) {
        client.write_all(&[0x05, 0xFF])?; // no acceptable methods
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no supported auth method",
        ));
    }
    client.write_all(&[0x05, 0x00])?; // no auth required

    // 2. Request
    client.read_exact(&mut buf[..4])?;
    if buf[0] != 0x05 || buf[1] != 0x01 {
        // Only CONNECT (0x01) is supported
        send_socks5_reply(&mut client, 0x07)?; // command not supported
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only CONNECT supported",
        ));
    }

    let addr = match buf[3] {
        0x01 => {
            // IPv4
            client.read_exact(&mut buf[..4])?;
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = read_port(&mut client)?;
            format!("{}:{}", ip, port)
        }
        0x03 => {
            // Domain name
            client.read_exact(&mut buf[..1])?;
            let len = buf[0] as usize;
            client.read_exact(&mut buf[..len])?;
            let domain = String::from_utf8_lossy(&buf[..len]).to_string();
            let port = read_port(&mut client)?;
            format!("{}:{}", domain, port)
        }
        0x04 => {
            // IPv6
            let mut ipv6_buf = [0u8; 16];
            client.read_exact(&mut ipv6_buf)?;
            let ip = std::net::Ipv6Addr::from(ipv6_buf);
            let port = read_port(&mut client)?;
            format!("[{}]:{}", ip, port)
        }
        _ => {
            send_socks5_reply(&mut client, 0x08)?; // address type not supported
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            ));
        }
    };

    // 3. Connect via Tailscale (routed through exit node)
    let remote = match ts.dial("tcp", &addr) {
        Ok(stream) => stream,
        Err(e) => {
            send_socks5_reply(&mut client, 0x05)?; // connection refused
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("dial {}: {}", addr, e),
            ));
        }
    };

    // 4. Send success reply
    send_socks5_reply(&mut client, 0x00)?;

    // 5. Relay data bidirectionally
    relay(client, remote);
    Ok(())
}

fn read_port(stream: &mut TcpStream) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn send_socks5_reply(client: &mut TcpStream, status: u8) -> io::Result<()> {
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    client.write_all(&[
        0x05, status, 0x00, 0x01, // SOCKS5, status, reserved, IPv4
        0, 0, 0, 0, // BND.ADDR = 0.0.0.0
        0, 0, // BND.PORT = 0
    ])
}

fn relay(client: TcpStream, remote: TcpStream) {
    let client2 = client.try_clone().unwrap();
    let remote2 = remote.try_clone().unwrap();

    let t1 = thread::spawn(move || copy_stream(client, remote));
    let t2 = thread::spawn(move || copy_stream(remote2, client2));

    let _ = t1.join();
    let _ = t2.join();
}

fn copy_stream(mut reader: TcpStream, mut writer: TcpStream) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown(Shutdown::Write);
}

// -- LocalAPI integration for exit node configuration --

fn set_exit_node(loopback: &libtailscale::Loopback, exit_node: &str, allow_lan: bool) {
    let body = format!(
        r#"{{"ExitNodeIP":"{}","ExitNodeAllowLANAccess":{},"ExitNodeIPSet":true,"ExitNodeAllowLANAccessSet":true}}"#,
        exit_node, allow_lan
    );

    let auth = base64_encode(&format!("tsnet:{}", loopback.credential));

    let request = format!(
        "PATCH /localapi/v0/prefs HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: Basic {}\r\n\
         Sec-Tailscale: localapi\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        loopback.address,
        auth,
        body.len(),
        body
    );

    let mut stream = TcpStream::connect(&loopback.address).unwrap_or_else(|e| {
        eprintln!(
            "[fatal] Failed to connect to LocalAPI at {}: {}",
            loopback.address, e
        );
        process::exit(1);
    });
    stream.write_all(request.as_bytes()).unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        let status_line = response.lines().next().unwrap_or("(empty response)");
        eprintln!("[fatal] Failed to set exit node: {}", status_line);
        if let Some(body_start) = response.find("\r\n\r\n") {
            eprintln!("[fatal] Response: {}", &response[body_start + 4..]);
        }
        process::exit(1);
    }
}

/// Minimal base64 encoder (no external dependency needed)
fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[(triple >> 18 & 0x3F) as usize] as char);
        result.push(CHARS[(triple >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[(triple >> 6 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// -- Argument parsing --

struct Args {
    exit_node: String,
    listen: String,
    hostname: Option<String>,
    allow_lan: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        exit_node: String::new(),
        listen: "127.0.0.1:1080".to_string(),
        hostname: None,
        allow_lan: false,
    };

    let argv: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--exit-node" => {
                i += 1;
                args.exit_node = argv.get(i).cloned().unwrap_or_default();
            }
            "--listen" => {
                i += 1;
                args.listen = argv.get(i).cloned().unwrap_or_default();
            }
            "--hostname" => {
                i += 1;
                args.hostname = argv.get(i).cloned();
            }
            "--allow-lan" => {
                args.allow_lan = true;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: socks5_proxy [OPTIONS]\n\n\
                     Options:\n  \
                       --exit-node <IP>    Exit node IP or MagicDNS name (required)\n  \
                       --listen <ADDR>     SOCKS5 listen address (default: 127.0.0.1:1080)\n  \
                       --hostname <NAME>   Tailscale hostname (default: auto)\n  \
                       --allow-lan         Allow LAN access when using exit node\n\n\
                     Environment:\n  \
                       TS_AUTHKEY          Tailscale auth key"
                );
                process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                process::exit(1);
            }
        }
        i += 1;
    }

    if args.exit_node.is_empty() {
        eprintln!("[fatal] --exit-node is required. Use --help for usage.");
        process::exit(1);
    }

    args
}
