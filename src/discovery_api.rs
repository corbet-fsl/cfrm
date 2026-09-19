//! HTTP adapter for signed discovery requests. No access logger is installed.
use crate::{
    discovery::{DiscoveryService, DiscoveryStore},
    Error,
};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone, Debug)]
pub struct DiscoveryHttpLimits {
    pub max_concurrent_requests: usize,
    pub body_timeout_millis: u64,
    /// Exact API authorities, optionally including a port. None delegates host
    /// routing to the trusted embedding; an empty allowlist is never accepted.
    pub allowed_hosts: Option<Vec<String>>,
}

struct ApiState<S> {
    service: Arc<DiscoveryService<S>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    concurrency: Arc<Semaphore>,
    body_timeout: Duration,
    allowed_hosts: Option<Vec<String>>,
}

/// Mount behind the application's authenticated transport. The HTTP handler
/// itself verifies issuer, root/device authority and each signed body; neither
/// cookies nor a client-supplied admission boolean grant authority.
pub fn router<S: DiscoveryStore + 'static>(
    service: Arc<DiscoveryService<S>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    limits: DiscoveryHttpLimits,
) -> Result<Router, Error> {
    if limits.max_concurrent_requests == 0
        || limits.max_concurrent_requests > Semaphore::MAX_PERMITS
        || limits.body_timeout_millis == 0
    {
        return Err(Error::InvalidInput);
    }
    let allowed_hosts = limits
        .allowed_hosts
        .map(|hosts| {
            if hosts.is_empty() || hosts.len() > 256 {
                return Err(Error::InvalidInput);
            }
            hosts
                .iter()
                .map(|host| normalize_host(host).ok_or(Error::InvalidInput))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let state = Arc::new(ApiState {
        service,
        clock,
        allowed_hosts,
        concurrency: Arc::new(Semaphore::new(limits.max_concurrent_requests)),
        body_timeout: Duration::from_millis(limits.body_timeout_millis),
    });
    Ok(Router::new()
        .route("/v1/discovery", post(handle::<S>))
        .with_state(state))
}

fn normalize_host(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 259 || !value.is_ascii() {
        return None;
    }
    let authority: axum::http::uri::Authority = value.parse().ok()?;
    let host = authority.host();
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || authority.port().is_some_and(|port| port.as_u16() == 0)
    {
        return None;
    }
    // Parsing must not silently discard user information, whitespace or bytes.
    let expected = match authority.port() {
        Some(port) => format!("{host}:{}", port.as_str()),
        None => host.to_owned(),
    };
    if expected != value {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn rejected(status: StatusCode) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "{\"error\":\"discovery request rejected\"}",
    )
        .into_response()
}

async fn handle<S: DiscoveryStore + 'static>(
    State(state): State<Arc<ApiState<S>>>,
    request: Request,
) -> Response {
    // Admission precedes body buffering, so slow clients cannot allocate an
    // unbounded number of maximum-size request bodies.
    let permit = match state.concurrency.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return rejected(StatusCode::TOO_MANY_REQUESTS),
    };
    if let Some(allowed) = &state.allowed_hosts {
        // Never trust X-Forwarded-Host or infer authority/roles from a hostname.
        let mut hosts = request.headers().get_all(header::HOST).iter();
        let actual = hosts
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(normalize_host);
        if hosts.next().is_some() || actual.as_ref().is_none_or(|host| !allowed.contains(host)) {
            return rejected(StatusCode::MISDIRECTED_REQUEST);
        }
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return rejected(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let input = match tokio::time::timeout(
        state.body_timeout,
        to_bytes(
            request.into_body(),
            state.service.limits().max_request_bytes,
        ),
    )
    .await
    {
        Ok(Ok(input)) => input,
        Ok(Err(_)) => return rejected(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => return rejected(StatusCode::REQUEST_TIMEOUT),
    };
    let completed = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // Read the trusted clock after queueing and body receipt, not before.
        let now = (state.clock)();
        state.service.execute_bytes(&input, now)
    })
    .await;
    match completed {
        Ok(Ok(result)) => match serde_json::to_vec(&result) {
            Ok(bytes) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                bytes,
            )
                .into_response(),
            Err(_) => rejected(StatusCode::SERVICE_UNAVAILABLE),
        },
        Ok(Err(Error::Capacity)) => rejected(StatusCode::TOO_MANY_REQUESTS),
        Ok(Err(Error::Storage | Error::ClockRollback)) | Err(_) => {
            rejected(StatusCode::SERVICE_UNAVAILABLE)
        }
        Ok(Err(_)) => rejected(StatusCode::FORBIDDEN),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_host;

    #[test]
    fn host_allowlist_normalizes_ascii_case_and_rejects_ambiguous_authority() {
        assert_eq!(
            normalize_host("API.Example.TEST:8443"),
            Some("api.example.test:8443".into())
        );
        for invalid in [
            "",
            "api.example.test.",
            "a..test",
            "-a.test",
            "a-.test",
            "user@api.example.test",
            "api.example.test/path",
            "api.example.test:0",
            "api.example.test:70000",
            " api.example.test",
            "api.exämple.test",
            "*.example.test",
        ] {
            assert_eq!(normalize_host(invalid), None, "{invalid}");
        }
    }
}
