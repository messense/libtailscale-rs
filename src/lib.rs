use std::ffi::{CStr, CString};
use std::iter::FusedIterator;
use std::net::{IpAddr, TcpStream};
use std::os::fd::FromRawFd;
use std::os::raw::c_int;

use libtailscale_sys::*;

/// A handle onto a Tailscale server
#[derive(Debug)]
pub struct Tailscale {
    inner: tailscale,
}

/// A socket on the tailnet listening for connections.
#[derive(Debug)]
pub struct Listener<'a> {
    tailscale: &'a Tailscale,
    listener: tailscale_listener,
}

impl Tailscale {
    /// Create a tailscale server object
    ///
    /// No network connection is initialized until [`Tailscale::start`] is called.
    pub fn new() -> Self {
        let inner = unsafe { tailscale_new() };
        Self { inner }
    }

    /// Connect the server to the tailnet
    ///
    /// Calling this function is optional as it will be called by the first use
    /// of [`Tailscale::listen`] or [`Tailscale::dial`] on a server
    pub fn start(&mut self) -> Result<(), String> {
        let ret = unsafe { tailscale_start(self.inner) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Connect the server to the tailnet and waits for it to be usable
    ///
    /// To cancel an in-progress call, use [`Tailscale::close`]
    pub fn up(&mut self) -> Result<(), String> {
        let ret = unsafe { tailscale_up(self.inner) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Shut down the server
    fn close(&mut self) -> Result<(), ()> {
        let ret = unsafe { tailscale_close(self.inner) };
        if ret != 0 {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Set the name of the directory to use for state.
    pub fn set_dir(&mut self, dir: &str) -> Result<(), String> {
        let dir = CString::new(dir).unwrap();
        let ret = unsafe { tailscale_set_dir(self.inner, dir.as_ptr()) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Set the hostname to present to the control server
    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), String> {
        let hostname = CString::new(hostname).unwrap();
        let ret = unsafe { tailscale_set_hostname(self.inner, hostname.as_ptr()) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Set the auth key to create the node and will be preferred over the
    /// `TS_AUTHKEY` environment variable.
    pub fn set_authkey(&mut self, authkey: &str) -> Result<(), String> {
        let authkey = CString::new(authkey).unwrap();
        let ret = unsafe { tailscale_set_authkey(self.inner, authkey.as_ptr()) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Set the URL of the coordination server to use.
    ///
    /// If empty or unset, the Tailscale default is used.
    pub fn set_control_url(&mut self, control_url: &str) -> Result<(), String> {
        let control_url = CString::new(control_url).unwrap();
        let ret = unsafe { tailscale_set_control_url(self.inner, control_url.as_ptr()) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Specifies whether the node should be ephemeral.
    pub fn set_ephemeral(&mut self, ephemeral: bool) -> Result<(), String> {
        let ret = unsafe { tailscale_set_ephemeral(self.inner, ephemeral as _) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Instruct the tailscale instance to write logs to `logfd`
    ///
    /// An `logfd` value of `-1` means discard all logging.
    pub fn set_logfd(&mut self, logfd: c_int) -> Result<(), String> {
        let ret = unsafe { tailscale_set_logfd(self.inner, logfd) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Returns the IP addresses of the Tailscale server.
    ///
    /// The result is typically an IPv4 and an IPv6 address, but may be empty
    /// or contain any number of addresses.
    pub fn get_ips(&self) -> Result<Vec<IpAddr>, String> {
        let mut buf = [0i8; 1024];
        let ret = unsafe { tailscale_getips(self.inner, buf.as_mut_ptr(), buf.len()) };
        if ret != 0 {
            Err(self.last_error())
        } else {
            let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
            let s = cstr.to_str().map_err(|e| e.to_string())?;
            if s.is_empty() {
                return Ok(Vec::new());
            }
            s.split(',')
                .map(|ip| ip.parse::<IpAddr>().map_err(|e| e.to_string()))
                .collect()
        }
    }

    /// Connect to the address on the tailnet.
    ///
    /// * `network` is a string of the form "tcp", "udp", etc.
    /// * `address` is a string of an IP address or domain name.
    ///
    /// It will start the server if it has not been started yet.
    pub fn dial(&self, network: &str, address: &str) -> Result<TcpStream, String> {
        let c_network = CString::new(network).unwrap();
        let c_address = CString::new(address).unwrap();
        let mut conn = 0;
        let ret = unsafe {
            tailscale_dial(
                self.inner,
                c_network.as_ptr(),
                c_address.as_ptr(),
                &mut conn,
            )
        };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(unsafe { TcpStream::from_raw_fd(conn) })
        }
    }

    /// Listen for a connection on the tailnet.
    ///
    /// * `network` is a string of the form "tcp", "udp", etc.
    /// * `address` is a string of an IP address or domain name.
    ///
    /// It will start the server if it has not been started yet.
    pub fn listen(&self, network: &str, address: &str) -> Result<Listener<'_>, String> {
        let c_network = CString::new(network).unwrap();
        let c_address = CString::new(address).unwrap();
        let mut listener = 0;
        let ret = unsafe {
            tailscale_listen(
                self.inner,
                c_network.as_ptr(),
                c_address.as_ptr(),
                &mut listener,
            )
        };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(Listener {
                tailscale: self,
                listener,
            })
        }
    }

    /// Start a LocalAPI listener on a loopback address, and returns the address
    /// and credentials for using it as LocalAPI or a proxy.
    pub fn loopback(&mut self) -> Result<Loopback, String> {
        let mut addr = [0; 1024];
        let mut cred = [0; 33];
        let mut proxy_cred = [0; 33];
        let ret = unsafe {
            tailscale_loopback(
                self.inner,
                addr.as_mut_ptr(),
                addr.len(),
                proxy_cred.as_mut_ptr(),
                cred.as_mut_ptr(),
            )
        };
        if ret != 0 {
            Err(self.last_error())
        } else {
            let addr = unsafe { CStr::from_ptr(addr.as_ptr()) };
            let cred = unsafe { CStr::from_ptr(cred.as_ptr()) };
            let proxy_cred = unsafe { CStr::from_ptr(proxy_cred.as_ptr()) };
            Ok(Loopback {
                address: addr.to_str().unwrap().to_owned(),
                credential: cred.to_str().unwrap().to_owned(),
                proxy_username: "tsnet",
                proxy_credential: proxy_cred.to_str().unwrap().to_owned(),
            })
        }
    }

    /// Configures it to have Tailscale Funnel enabled, routing requests from the public web
    /// (without any authentication) down to this Tailscale node, requesting new
    /// LetsEncrypt TLS certs as needed, terminating TLS, and proxying all incoming
    /// HTTPS requests to `http://127.0.0.1:localhost_port` without TLS.
    ///
    /// There should be a plaintext HTTP/1 server listening on `127.0.0.1:localhost_port`
    /// or tsnet will serve HTTP 502 errors.
    ///
    /// Expect junk traffic from the internet from bots watching the public CT logs.
    pub fn enable_funnel_to_localhost_plaintext_http1(
        &self,
        localhost_port: u16,
    ) -> Result<(), String> {
        let ret = unsafe {
            tailscale_enable_funnel_to_localhost_plaintext_http1(self.inner, localhost_port as _)
        };
        if ret != 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    fn last_error(&self) -> String {
        let mut buffer = [0; 256];
        let ret = unsafe { tailscale_errmsg(self.inner, buffer.as_mut_ptr(), buffer.len() as _) };
        if ret != 0 {
            return "tailscale internal error: failed to get error message".to_string();
        }
        let cstr = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        cstr.to_string_lossy().into_owned()
    }
}

impl Drop for Tailscale {
    fn drop(&mut self) {
        let _ret = self.close();
    }
}

impl Default for Tailscale {
    fn default() -> Self {
        Self::new()
    }
}

/// Tailscale loopback API information.
#[derive(Debug, Clone)]
pub struct Loopback {
    /// `ip:port` address of the LocalAPI
    pub address: String,
    /// Basic auth password
    pub credential: String,
    /// Proxy username, it's always `tsnet`
    pub proxy_username: &'static str,
    /// Proxy auth password
    pub proxy_credential: String,
}

impl<'a> Listener<'a> {
    /// Accept a connection on a Tailscale [`Listener`].
    pub fn accept(&self) -> Result<TcpStream, String> {
        let mut conn = 0;
        let ret = unsafe { tailscale_accept(self.listener, &mut conn) };
        if ret != 0 {
            Err(self.tailscale.last_error())
        } else {
            Ok(unsafe { TcpStream::from_raw_fd(conn) })
        }
    }

    /// Returns the remote address for an incoming connection.
    ///
    /// The `conn` should be a raw file descriptor obtained from [`Listener::accept_raw`]
    /// or the raw fd of a `TcpStream` returned by [`Listener::accept`].
    pub fn get_remote_addr(&self, conn: tailscale_conn) -> Result<IpAddr, String> {
        let mut buf = [0i8; 256];
        let ret =
            unsafe { tailscale_getremoteaddr(self.listener, conn, buf.as_mut_ptr(), buf.len()) };
        if ret != 0 {
            Err(self.tailscale.last_error())
        } else {
            let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
            let s = cstr.to_str().map_err(|e| e.to_string())?;
            s.parse::<IpAddr>().map_err(|e| e.to_string())
        }
    }

    /// Accept a connection on a Tailscale [`Listener`], returning the raw
    /// file descriptor and the remote address.
    pub fn accept_with_addr(&self) -> Result<(TcpStream, IpAddr), String> {
        let mut conn = 0;
        let ret = unsafe { tailscale_accept(self.listener, &mut conn) };
        if ret != 0 {
            return Err(self.tailscale.last_error());
        }
        let addr = self.get_remote_addr(conn)?;
        let stream = unsafe { TcpStream::from_raw_fd(conn) };
        Ok((stream, addr))
    }

    /// Returns an iterator over the connections being received on this
    /// listener.
    ///
    /// The returned iterator will never return [`None`]. Iterating over it is equivalent to
    /// calling [`Listener::accept`] in a loop.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Close the listener.
    fn close(&mut self) -> Result<(), String> {
        let ret = unsafe { libc::close(self.listener) };
        if ret != 0 {
            Err(self.tailscale.last_error())
        } else {
            Ok(())
        }
    }
}

impl<'a> Drop for Listener<'a> {
    fn drop(&mut self) {
        let _ret = self.close();
    }
}

/// An iterator that infinitely accepts connections on a [`Listener`].
#[must_use = "iterators are lazy and do nothing unless consumed"]
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a Listener<'a>,
}

impl<'a> Iterator for Incoming<'a> {
    type Item = Result<TcpStream, String>;
    fn next(&mut self) -> Option<Result<TcpStream, String>> {
        Some(self.listener.accept())
    }
}

impl FusedIterator for Incoming<'_> {}
