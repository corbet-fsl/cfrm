//! Bounded HTTP adapter. No access logger, durable storage or proxy-header trust.
use crate::{Call, ErrorCode, Failure, actions, execute};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

pub struct Limits {
    pub hosts: Vec<String>,
    pub origins: Vec<String>,
    pub body_bytes: usize,
    pub concurrent: usize,
    pub body_timeout: Duration,
}
struct Config {
    limits: Limits,
    concurrent: Semaphore,
}

pub fn router(limits: Limits) -> Result<Router, ErrorCode> {
    if limits.hosts.is_empty()
        || limits.origins.is_empty()
        || limits.body_bytes == 0
        || limits.body_bytes > 1_048_576
        || limits.concurrent == 0
        || limits.concurrent > 4096
        || limits.body_timeout.is_zero()
    {
        return Err(ErrorCode::InvalidRequest);
    }
    for host in &limits.hosts {
        let url = url::Url::parse(&format!("https://{host}")).map_err(|_| ErrorCode::Host)?;
        // The fixed HTTPS scheme makes URL's parser reject an empty host.
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || url.authority() != host
        {
            return Err(ErrorCode::Host);
        }
    }
    for origin in &limits.origins {
        let url = url::Url::parse(origin).map_err(|_| ErrorCode::Origin)?;
        if url.scheme() != "https" || url.origin().ascii_serialization() != *origin {
            return Err(ErrorCode::Origin);
        }
    }
    let state = Arc::new(Config {
        concurrent: Semaphore::new(limits.concurrent),
        limits,
    });
    let mut router = Router::new();
    for action in actions() {
        router = router.route(&format!("/v1/{}", action.name), post(handle));
    }
    Ok(router
        .fallback(|| async { reject(ErrorCode::InvalidRequest) })
        .method_not_allowed_fallback(|| async { reject(ErrorCode::InvalidRequest) })
        .with_state(state))
}

fn reject(error: ErrorCode) -> Response {
    let status = match error {
        ErrorCode::Host => StatusCode::MISDIRECTED_REQUEST,
        ErrorCode::Origin => StatusCode::FORBIDDEN,
        ErrorCode::Capacity => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::Timeout => StatusCode::REQUEST_TIMEOUT,
        ErrorCode::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::MediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ErrorCode::AuthorityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(Failure { error }),
    )
        .into_response()
}

fn exact_header(request: &Request, name: header::HeaderName, allowed: &[String]) -> bool {
    let mut values = request.headers().get_all(name).iter();
    let valid = values
        .next()
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| allowed.iter().any(|a| a == v));
    valid && values.next().is_none()
}

async fn handle(State(config): State<Arc<Config>>, request: Request) -> Response {
    if !exact_header(&request, header::HOST, &config.limits.hosts) {
        return reject(ErrorCode::Host);
    }
    if !exact_header(&request, header::ORIGIN, &config.limits.origins) {
        return reject(ErrorCode::Origin);
    }
    if !exact_header(&request, header::CONTENT_TYPE, &["application/json".into()]) {
        return reject(ErrorCode::MediaType);
    }
    let Ok(_permit) = config.concurrent.try_acquire() else {
        return reject(ErrorCode::Capacity);
    };
    let path = request.uri().path().to_owned();
    let bytes = match tokio::time::timeout(
        config.limits.body_timeout,
        to_bytes(request.into_body(), config.limits.body_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return reject(ErrorCode::TooLarge),
        Err(_) => return reject(ErrorCode::Timeout),
    };
    let call = match Call::decode(&bytes, config.limits.body_bytes) {
        Ok(call) => call,
        Err(error) => return reject(error),
    };
    if path != format!("/v1/{}", call.request.info().name) {
        return reject(ErrorCode::InvalidRequest);
    }
    match execute(&call) {
        Err(error) => reject(error),
        Ok(impossible) => match impossible {},
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
