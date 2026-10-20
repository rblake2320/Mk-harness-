//! Egress allowlist for every outbound HTTP call the kernel makes. Only
//! HTTPS (or plain HTTP to loopback for the local simulator), no embedded
//! credentials, no query/fragment, authority must be allowlisted, and IP
//! literals must be global (no SSRF into private ranges).

use std::collections::HashSet;
use std::net::IpAddr;

use url::{Host, Url};

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    #[error("url malformed")]
    Malformed,
    #[error("scheme not allowed")]
    Scheme,
    #[error("credentials in url")]
    Credentials,
    #[error("query or fragment not allowed")]
    QueryOrFragment,
    #[error("authority not allowlisted")]
    NotAllowlisted,
    #[error("non-global ip literal")]
    PrivateAddress,
}

#[derive(Debug, Clone, Default)]
pub struct EgressAllowlist {
    authorities: HashSet<String>,
    allow_loopback_http: bool,
}

impl EgressAllowlist {
    #[must_use]
    pub fn new<'a>(
        authorities: impl IntoIterator<Item = &'a str>,
        allow_loopback_http: bool,
    ) -> Self {
        Self {
            authorities: authorities
                .into_iter()
                .map(|a| {
                    a.trim()
                        .to_ascii_lowercase()
                        .trim_end_matches('.')
                        .to_owned()
                })
                .collect(),
            allow_loopback_http,
        }
    }

    /// Validate and return the normalized URL.
    pub fn check(&self, raw: &str) -> Result<Url, EgressError> {
        let url = Url::parse(raw).map_err(|_| EgressError::Malformed)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::Credentials);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(EgressError::QueryOrFragment);
        }
        let host = url.host().ok_or(EgressError::Malformed)?;
        let is_loopback = match &host {
            Host::Ipv4(ip) => ip.is_loopback(),
            Host::Ipv6(ip) => ip.is_loopback(),
            Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        };
        match url.scheme() {
            "https" => {}
            "http" if self.allow_loopback_http && is_loopback => {}
            _ => return Err(EgressError::Scheme),
        }
        if let Host::Ipv4(ip) = host
            && !self.allow_loopback_http
            && !is_global_v4(ip)
        {
            return Err(EgressError::PrivateAddress);
        }
        if let Host::Ipv6(ip) = host
            && !self.allow_loopback_http
            && !is_global_v6(ip)
        {
            return Err(EgressError::PrivateAddress);
        }
        let authority = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        }
        .to_ascii_lowercase();
        if !self.authorities.contains(&authority) {
            return Err(EgressError::NotAllowlisted);
        }
        Ok(url)
    }
}

fn is_global_v4(ip: std::net::Ipv4Addr) -> bool {
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation() || ip.is_unspecified()
        || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]) // CGNAT
        || ip.octets()[0] == 169 && ip.octets()[1] == 254)
}

fn is_global_v6(ip: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(v4);
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80)
}

#[allow(dead_code)]
fn _ip_type_check(_: IpAddr) {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    fn al() -> EgressAllowlist {
        EgressAllowlist::new(
            [
                "adapter.example.com",
                "adapter.example.com:8443",
                "127.0.0.1:8787",
            ],
            true,
        )
    }

    #[test]
    fn allowlisted_https_passes() {
        assert!(
            al().check("https://adapter.example.com/api/agent-ops/tasks/x/result")
                .is_ok()
        );
        assert!(al().check("https://ADAPTER.example.com:8443/x").is_ok());
        assert!(
            al().check("http://127.0.0.1:8787/sim").is_ok(),
            "loopback http only when explicitly allowed"
        );
    }

    #[test]
    fn ssrf_and_shape_rejections() {
        let a = al();
        assert_eq!(
            a.check("http://adapter.example.com/x").err(),
            Some(EgressError::Scheme)
        );
        assert_eq!(
            a.check("https://user:pw@adapter.example.com/x").err(),
            Some(EgressError::Credentials)
        );
        assert_eq!(
            a.check("https://adapter.example.com/x?y=1").err(),
            Some(EgressError::QueryOrFragment)
        );
        assert_eq!(
            a.check("https://evil.example.com/x").err(),
            Some(EgressError::NotAllowlisted)
        );
        assert_eq!(
            a.check("https://adapter.example.com.evil.com/x").err(),
            Some(EgressError::NotAllowlisted)
        );
        assert_eq!(
            a.check("https://169.254.169.254/latest/meta-data").err(),
            Some(EgressError::NotAllowlisted)
        );
        let strict = EgressAllowlist::new(["10.0.0.5", "169.254.169.254", "[::1]"], false);
        assert_eq!(
            strict.check("https://10.0.0.5/x").err(),
            Some(EgressError::PrivateAddress)
        );
        assert_eq!(
            strict.check("https://169.254.169.254/x").err(),
            Some(EgressError::PrivateAddress)
        );
        assert_eq!(
            strict.check("https://[::1]/x").err(),
            Some(EgressError::PrivateAddress)
        );
        assert!(matches!(
            a.check("file:///etc/passwd").err(),
            Some(EgressError::Scheme | EgressError::Malformed)
        ));
        assert!(a.check("not a url").is_err());
    }
}
