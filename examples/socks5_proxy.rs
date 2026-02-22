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
use std::io;
use std::net::Ipv6Addr;
use std::process;
use std::sync::Arc;

use libtailscale::Tailscale;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() {
    let args = parse_args();

    eprintln!("[info] Starting tailscale node...");
    let mut ts = Tailscale::new();
    ts.set_ephemeral(true).unwrap();
    if let Some(ref hostname) = args.hostname {
        ts.set_hostname(hostname).unwrap();
    }
    ts.set_logfd(-1).unwrap();
    ts.up().unwrap();

    let ips = ts.get_ips().unwrap();
    eprintln!("[info] Tailscale is up, IPs: {:?}", ips);

    // Configure exit node via LocalAPI
    let loopback = ts.loopback().unwrap();
    eprintln!("[info] LocalAPI at {}", loopback.address);

    set_exit_node(&loopback, &args.exit_node, args.allow_lan).await;
    eprintln!("[info] Exit node set to: {}", args.exit_node);

    let ts = Arc::new(ts);

    // Start SOCKS5 proxy on local address
    let listener = TcpListener::bind(&args.listen).await.unwrap_or_else(|e| {
        eprintln!("[fatal] Failed to bind {}: {}", args.listen, e);
        process::exit(1);
    });
    eprintln!("[info] SOCKS5 proxy listening on socks5://{}", args.listen);

    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                let ts = Arc::clone(&ts);
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5(client, ts).await {
                        eprintln!("[error] {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[error] Accept failed: {}", e),
        }
    }
}

// -- SOCKS5 implementation (no-auth, CONNECT only) --

async fn handle_socks5(mut client: TcpStream, ts: Arc<Tailscale>) -> io::Result<()> {
    // 1. Greeting
    let mut buf = [0u8; 258];
    client.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods]).await?;

    if !buf[..nmethods].contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no supported auth method",
        ));
    }
    client.write_all(&[0x05, 0x00]).await?;

    // 2. Request
    client.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 || buf[1] != 0x01 {
        send_socks5_reply(&mut client, 0x07).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only CONNECT supported",
        ));
    }

    let addr = match buf[3] {
        0x01 => {
            // IPv4
            client.read_exact(&mut buf[..4]).await?;
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = read_port(&mut client).await?;
            format!("{ip}:{port}")
        }
        0x03 => {
            // Domain name
            client.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            client.read_exact(&mut buf[..len]).await?;
            let domain = String::from_utf8_lossy(&buf[..len]).to_string();
            let port = read_port(&mut client).await?;
            format!("{domain}:{port}")
        }
        0x04 => {
            // IPv6
            let mut ipv6_buf = [0u8; 16];
            client.read_exact(&mut ipv6_buf).await?;
            let ip = Ipv6Addr::from(ipv6_buf);
            let port = read_port(&mut client).await?;
            format!("[{ip}]:{port}")
        }
        _ => {
            send_socks5_reply(&mut client, 0x08).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            ));
        }
    };

    // 3. Connect via Tailscale (blocking dial in spawn_blocking)
    let ts_clone = Arc::clone(&ts);
    let addr_clone = addr.clone();
    let std_stream = tokio::task::spawn_blocking(move || ts_clone.dial("tcp", &addr_clone))
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("dial {addr}: {e}"),
            )
        })?;

    std_stream.set_nonblocking(true)?;
    let mut remote = TcpStream::from_std(std_stream)?;

    // 4. Send success reply
    send_socks5_reply(&mut client, 0x00).await?;

    // 5. Relay data bidirectionally
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    Ok(())
}

async fn read_port(stream: &mut TcpStream) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

async fn send_socks5_reply(client: &mut TcpStream, status: u8) -> io::Result<()> {
    client
        .write_all(&[
            0x05, status, 0x00, 0x01, // SOCKS5, status, reserved, IPv4
            0, 0, 0, 0, // BND.ADDR = 0.0.0.0
            0, 0, // BND.PORT = 0
        ])
        .await
}

// -- LocalAPI integration for exit node configuration --

async fn set_exit_node(loopback: &libtailscale::Loopback, exit_node: &str, allow_lan: bool) {
    let exit_node_ip = if exit_node.parse::<std::net::IpAddr>().is_ok() {
        exit_node.to_string()
    } else {
        resolve_exit_node(loopback, exit_node).await
    };

    let body = format!(
        r#"{{"ExitNodeIP":"{exit_node_ip}","ExitNodeAllowLANAccess":{allow_lan},"ExitNodeIPSet":true,"ExitNodeAllowLANAccessSet":true}}"#,
    );

    let response = localapi_request(loopback, "PATCH", "/localapi/v0/prefs", Some(&body)).await;
    let (status_line, resp_body) = parse_http_response(&response);
    if !status_line.contains("200") {
        eprintln!("[fatal] Failed to set exit node: {status_line}");
        eprintln!("[fatal] Response: {resp_body}");
        process::exit(1);
    }
}

async fn resolve_exit_node(loopback: &libtailscale::Loopback, name: &str) -> String {
    let response = localapi_request(loopback, "GET", "/localapi/v0/status", None).await;
    let (_status, body) = parse_http_response(&response);

    let name_lower = name.to_lowercase();
    let name_lower = name_lower.trim_end_matches('.');

    let mut search_pos = 0;
    while let Some(dns_idx) = body[search_pos..].find("\"DNSName\"") {
        let abs_dns_idx = search_pos + dns_idx;

        let dns_name = extract_json_string(body, abs_dns_idx).unwrap_or_default();
        let dns_name_lower = dns_name.to_lowercase();
        let dns_name_trimmed = dns_name_lower.trim_end_matches('.');

        let chunk_start = abs_dns_idx.saturating_sub(200);
        let chunk_end = (abs_dns_idx + 500).min(body.len());
        let chunk = &body[chunk_start..chunk_end];

        let host_name = chunk
            .find("\"HostName\"")
            .and_then(|i| extract_json_string(chunk, i))
            .unwrap_or_default()
            .to_lowercase();

        let matched = dns_name_trimmed == name_lower
            || dns_name_trimmed.starts_with(&format!("{name_lower}."))
            || host_name == name_lower;

        if matched {
            if let Some(ip) = chunk
                .find("\"TailscaleIPs\"")
                .and_then(|i| extract_json_array_first(chunk, i))
            {
                eprintln!("[info] Resolved exit node '{name}' -> {ip}");
                return ip;
            }
        }

        search_pos = abs_dns_idx + 10;
    }

    eprintln!("[fatal] Could not find exit node '{name}' in tailnet peers. Available peers:");
    let mut pos = 0;
    while let Some(idx) = body[pos..].find("\"DNSName\"") {
        let abs = pos + idx;
        if let Some(dns) = extract_json_string(body, abs) {
            eprintln!("  - {}", dns.trim_end_matches('.'));
        }
        pos = abs + 10;
    }
    process::exit(1);
}

fn extract_json_string(s: &str, key_pos: usize) -> Option<String> {
    let after_key = &s[key_pos..];
    let colon = after_key.find(':')?;
    let after_colon = &after_key[colon + 1..];
    let quote_start = after_colon.find('"')?;
    let value_start = quote_start + 1;
    let quote_end = after_colon[value_start..].find('"')?;
    Some(after_colon[value_start..value_start + quote_end].to_string())
}

fn extract_json_array_first(s: &str, key_pos: usize) -> Option<String> {
    let after_key = &s[key_pos..];
    let bracket = after_key.find('[')?;
    let after_bracket = &after_key[bracket + 1..];
    let quote_start = after_bracket.find('"')?;
    let value_start = quote_start + 1;
    let quote_end = after_bracket[value_start..].find('"')?;
    Some(after_bracket[value_start..value_start + quote_end].to_string())
}

fn parse_http_response(response: &str) -> (&str, &str) {
    let status_line = response.lines().next().unwrap_or("");
    let body = response
        .find("\r\n\r\n")
        .map(|pos| &response[pos + 4..])
        .unwrap_or("");
    (status_line, body)
}

/// Make an HTTP request to the LocalAPI using tokio TcpStream.
async fn localapi_request(
    loopback: &libtailscale::Loopback,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> String {
    let auth = base64_encode(&format!("tsnet:{}", loopback.credential));

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: Basic {auth}\r\n\
         Sec-Tailscale: localapi\r\n",
        loopback.address,
    );
    if let Some(b) = body {
        request.push_str(&format!(
            "Content-Type: application/json\r\n\
             Content-Length: {}\r\n",
            b.len()
        ));
    }
    request.push_str("Connection: close\r\n\r\n");
    if let Some(b) = body {
        request.push_str(b);
    }

    let mut stream = TcpStream::connect(&loopback.address)
        .await
        .unwrap_or_else(|e| {
            eprintln!(
                "[fatal] Failed to connect to LocalAPI at {}: {e}",
                loopback.address,
            );
            process::exit(1);
        });
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

/// Minimal base64 encoder (no external dependency needed).
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
                       --exit-node <NODE>  Exit node IP, hostname, or FQDN (required)\n  \
                       --listen <ADDR>     SOCKS5 listen address (default: 127.0.0.1:1080)\n  \
                       --hostname <NAME>   Tailscale hostname (default: auto)\n  \
                       --allow-lan         Allow LAN access when using exit node\n\n\
                     Environment:\n  \
                       TS_AUTHKEY          Tailscale auth key"
                );
                process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
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
