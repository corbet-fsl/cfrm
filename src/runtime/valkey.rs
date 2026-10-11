//! Startup policy for the Valkey backend. Presence rows carry public profiles
//! and ciphertext, so they never cross a network unencrypted and the backend
//! must not persist them (ephemeral state only).
use crate::ErrorCode;
use std::net::Ipv4Addr;
use url::{Host, Url};

/// Accept TLS (`rediss`), a local socket, or plaintext `redis` on loopback only.
/// A URL fragment is refused because the client reads `#insecure` from it to
/// switch certificate verification off.
pub fn check_url(url: &str) -> Result<(), ErrorCode> {
    let parsed = Url::parse(url).map_err(|_| ErrorCode::InvalidRequest)?;
    if parsed.fragment().is_some() {
        return Err(ErrorCode::InvalidRequest);
    }
    match parsed.scheme() {
        "rediss" | "redis+unix" | "unix" => Ok(()),
        "redis" => match parsed.host() {
            // Non-special schemes keep dotted IPv4 as an opaque domain string.
            Some(Host::Domain(name))
                if name.eq_ignore_ascii_case("localhost")
                    || name.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback()) =>
            {
                Ok(())
            }
            Some(Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
            _ => Err(ErrorCode::InvalidRequest),
        },
        _ => Err(ErrorCode::InvalidRequest),
    }
}

/// Persistence reported as enabled refuses startup. An unknown state is normal
/// on managed Valkey, where the configuration is not readable; the caller still
/// reports it to the operator.
pub fn check_persistence(warnings: &[cvtl::Warning]) -> Result<(), ErrorCode> {
    if warnings.contains(&cvtl::Warning::PersistenceEnabled) {
        return Err(ErrorCode::AuthorityUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_encrypted_local_or_loopback_urls_are_accepted() {
        for url in [
            "rediss://cache.example.test:6380/0",
            "rediss://user:secret@cache.example.test",
            "redis://localhost:6379",
            "redis://LOCALHOST",
            "redis://127.0.0.1:6379/1",
            "redis://127.1.2.3",
            "redis://[::1]:6379",
            "redis+unix:///run/valkey.sock",
            "unix:///run/valkey.sock",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "redis://cache.example.test:6379",
            "redis://10.0.0.5",
            "redis://[2001:db8::1]",
            "redis://192.168.1.1",
            "redis://127.1",
            "redis://[::2]",
            "redis:///no-host",
            "rediss://cache.example.test/#insecure",
            "redis://localhost/#x",
            "http://localhost",
            "not a url",
            "",
        ] {
            assert_eq!(check_url(url), Err(ErrorCode::InvalidRequest), "{url}");
        }
    }

    #[test]
    fn enabled_persistence_refuses_startup_but_unknown_does_not() {
        assert_eq!(check_persistence(&[]), Ok(()));
        assert_eq!(
            check_persistence(&[cvtl::Warning::PersistenceUnknown]),
            Ok(())
        );
        assert_eq!(
            check_persistence(&[
                cvtl::Warning::PersistenceUnknown,
                cvtl::Warning::PersistenceEnabled
            ]),
            Err(ErrorCode::AuthorityUnavailable)
        );
    }
}
