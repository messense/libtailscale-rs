//! To build and run it:
//!
//! ```bash
//! TS_AUTHKEY=<your-auth-key> cargo run --example http_echo_server
//! ```
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use libtailscale::Tailscale;

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.
async fn echo(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(full(
            "Try POSTing data to /echo such as: `curl echo-http-server:3000/echo -XPOST -d 'hello world'`",
        ))),

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body().boxed())),

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ts = Tailscale::new();
    ts.set_ephemeral(true).unwrap();
    ts.set_logfd(-1).unwrap();
    ts.up().unwrap();

    let loopback = ts.loopback().unwrap();
    println!(
        "Loopback API: {}, credential: {}",
        loopback.address, loopback.credential
    );
    println!(
        "Proxy username: {}, credential: {}",
        loopback.proxy_username, loopback.proxy_credential
    );
    println!();

    let listener = ts.listen("tcp", ":3000").unwrap();
    println!("Listening on http://echo-http-server:3000");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                stream.set_nonblocking(true)?;
                let stream = tokio::net::TcpStream::from_std(stream)?;
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(stream, service_fn(echo))
                        .await
                    {
                        println!("Error serving connection: {:?}", err);
                    }
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    Ok(())
}
