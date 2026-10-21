//! `mk-healthcheck <url>`: container health probe for distroless images (no
//! shell, no curl). Plain HTTP/1.1 GET over TCP to a loopback URL; exit 0 on a
//! 2xx status, 1 otherwise. No TLS by design — probes stay on 127.0.0.1.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: mk-healthcheck http://127.0.0.1:PORT/path");
        std::process::exit(2);
    };
    std::process::exit(i32::from(!probe(&url)));
}

fn probe(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(a, _)| (a, &rest[a.len()..]));
    let host = authority.split_once(':').map_or(authority, |(h, _)| h);
    if host != "127.0.0.1" && host != "localhost" {
        return false;
    }
    let Ok(mut addrs) = authority.to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: mk-healthcheck\r\n\r\n").as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    let Ok(n) = s.read(&mut buf) else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.0 2")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::probe;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve(status: &'static str) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        let addr = l.local_addr().unwrap_or_else(|e| panic!("{e}"));
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
                    .as_bytes(),
                );
            }
        });
        format!("http://{addr}/health/live")
    }

    #[test]
    fn two_hundred_is_healthy() {
        assert!(probe(&serve("200 OK")));
    }

    #[test]
    fn five_hundred_and_refused_and_non_loopback_are_unhealthy() {
        assert!(!probe(&serve("503 Service Unavailable")));
        assert!(!probe("http://127.0.0.1:9/health/live"));
        assert!(!probe("http://example.com/health/live"));
        assert!(!probe("https://127.0.0.1:1/health/live"));
    }
}
