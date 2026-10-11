//! Bounded HTTP adapter. No access logger, durable storage or proxy-header trust.
use crate::{
    Call, ErrorCode, Failure, Requirement, actions,
    bucket::{Bucket, Keyed},
    execute,
};
use axum::{
    Router,
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

/// How often idle source and session keys are dropped from RAM.
const PRUNE_INTERVAL: Duration = Duration::from_secs(30);

/// Longest session identifier a bucket will track; longer values are refused
/// before any owner work.
const SESSION_BYTES: usize = 64;

pub struct Limits {
    pub hosts: Vec<String>,
    pub origins: Vec<String>,
    pub body_bytes: usize,
    /// Total in-flight requests. `anonymous_concurrent` of them are reserved for
    /// pre-session actions, the rest serve current device sessions only.
    pub concurrent: usize,
    pub anonymous_concurrent: usize,
    pub body_timeout: Duration,
    /// Bound for the whole owner call after the body was read.
    pub request_timeout: Duration,
    /// Per network source (IPv4 address or IPv6 /64), RAM only.
    pub source: Bucket,
    /// Per session identifier, which bounds the replay markers one session can
    /// create within an authority interval. RAM only.
    pub session: Bucket,
}
struct Config {
    limits: Limits,
    anonymous: Semaphore,
    authenticated: Semaphore,
    anonymous_actions: BTreeSet<&'static str>,
    source: Keyed<IpAddr>,
    session: Keyed<Vec<u8>>,
    controller: Option<crate::runtime::Handle>,
}
impl Config {
    fn new(limits: Limits, controller: Option<crate::runtime::Handle>) -> Result<Self, ErrorCode> {
        if limits.concurrent == 0
            || limits.concurrent > 4096
            || limits.anonymous_concurrent == 0
            || limits.anonymous_concurrent >= limits.concurrent
            || limits.body_timeout.is_zero()
            || limits.request_timeout.is_zero()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let source = Keyed::new(limits.source).ok_or(ErrorCode::InvalidRequest)?;
        let session = Keyed::new(limits.session).ok_or(ErrorCode::InvalidRequest)?;
        Ok(Self {
            anonymous: Semaphore::new(limits.anonymous_concurrent),
            authenticated: Semaphore::new(limits.concurrent - limits.anonymous_concurrent),
            anonymous_actions: actions()
                .into_iter()
                .filter(|action| action.requirement != Requirement::CurrentDeviceSession)
                .map(|action| action.name)
                .collect(),
            source,
            session,
            controller,
            limits,
        })
    }
}

/// Drop idle keys on a timer for as long as the configuration lives. The task
/// holds only a weak reference, so it ends with the router.
fn spawn_pruner(config: &Arc<Config>, every: Duration) {
    let config = Arc::downgrade(config);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        loop {
            interval.tick().await;
            let Some(config) = config.upgrade() else {
                break;
            };
            config.source.prune();
            config.session.prune();
        }
    });
}

/// IPv4-mapped IPv6 collapses to IPv4 and other IPv6 addresses to their /64, so
/// one subscriber cannot take a fresh bucket per address. Without connection
/// information (in-process use) all requests share one bucket.
fn source(request: &Request) -> IpAddr {
    match request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
    {
        Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => {
                let mut octets = ip.octets();
                octets[8..].fill(0);
                IpAddr::V6(octets.into())
            }
        },
        Some(ip) => ip,
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

pub fn router(limits: Limits) -> Result<Router, ErrorCode> {
    configured(limits, None)
}

pub fn router_with(
    limits: Limits,
    controller: crate::runtime::Handle,
) -> Result<Router, ErrorCode> {
    configured(limits, Some(controller))
}

fn configured(
    limits: Limits,
    controller: Option<crate::runtime::Handle>,
) -> Result<Router, ErrorCode> {
    if limits.hosts.is_empty()
        || limits.origins.is_empty()
        || limits.body_bytes == 0
        || limits.body_bytes > 1_048_576
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
    let state = Arc::new(Config::new(limits, controller)?);
    // Without a runtime (in-process use) idle keys are still dropped whenever a
    // full table is hit.
    if tokio::runtime::Handle::try_current().is_ok() {
        spawn_pruner(&state, PRUNE_INTERVAL);
    }
    let mut router = Router::new();
    for action in actions() {
        router = router.route(
            &format!("/v1/{}", action.name),
            post(handle).options(preflight),
        );
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
    let origin = request.headers()[header::ORIGIN].clone();
    cors(origin, handle_allowed(config, request).await)
}

fn cors(origin: axum::http::HeaderValue, mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response
        .headers_mut()
        .insert(header::VARY, axum::http::HeaderValue::from_static("Origin"));
    response
}

async fn preflight(State(config): State<Arc<Config>>, request: Request) -> Response {
    if !exact_header(&request, header::HOST, &config.limits.hosts) {
        return reject(ErrorCode::Host);
    }
    if !exact_header(&request, header::ORIGIN, &config.limits.origins) {
        return reject(ErrorCode::Origin);
    }
    let origin = request.headers()[header::ORIGIN].clone();
    if !exact_header(
        &request,
        header::ACCESS_CONTROL_REQUEST_METHOD,
        &["POST".into()],
    ) {
        return cors(origin, reject(ErrorCode::InvalidRequest));
    }
    let mut headers = request
        .headers()
        .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .iter();
    let valid = headers
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("content-type"));
    if !valid || headers.next().is_some() {
        return cors(origin, reject(ErrorCode::InvalidRequest));
    }
    cors(
        origin,
        (
            StatusCode::NO_CONTENT,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::ACCESS_CONTROL_ALLOW_METHODS, "POST"),
                (header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
            ],
        )
            .into_response(),
    )
}

async fn handle_allowed(config: Arc<Config>, request: Request) -> Response {
    if !exact_header(&request, header::CONTENT_TYPE, &["application/json".into()]) {
        return reject(ErrorCode::MediaType);
    }
    // Cheapest refusal first: the per-source bucket runs before a permit, the
    // body read or any owner work.
    if !config.source.admit(&source(&request)) {
        return reject(ErrorCode::Capacity);
    }
    let path = request.uri().path().to_owned();
    // Pre-session actions cannot starve current device sessions.
    let pool = match path.strip_prefix("/v1/") {
        Some(name) if config.anonymous_actions.contains(name) => &config.anonymous,
        _ => &config.authenticated,
    };
    let Ok(_permit) = pool.try_acquire() else {
        return reject(ErrorCode::Capacity);
    };
    let origin = request.headers()[header::ORIGIN]
        .to_str()
        .expect("validated exact origin")
        .to_owned();
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
    if let Some(possession) = call.request.possession() {
        if possession.session.len() > SESSION_BYTES {
            return reject(ErrorCode::InvalidRequest);
        }
        if !config.session.admit(&possession.session) {
            return reject(ErrorCode::Capacity);
        }
    }
    let result = match &config.controller {
        Some(controller) => {
            match tokio::time::timeout(
                config.limits.request_timeout,
                controller.execute(origin, call),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(ErrorCode::Timeout),
            }
        }
        None => execute(&call),
    };
    match result {
        Err(error) => reject(error),
        Ok(reply) => ([(header::CACHE_CONTROL, "no-store")], axum::Json(reply)).into_response(),
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
