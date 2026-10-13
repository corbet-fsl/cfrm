use super::*;
use crate::*;
use axum::{body::Body, extract::Request};
use tower::ServiceExt;

fn bucket(burst: u32) -> Bucket {
    Bucket {
        burst,
        replenish: Duration::from_millis(1),
        keys: 16,
    }
}
fn limits() -> Limits {
    Limits {
        hosts: vec!["api.example.test".into()],
        origins: vec!["https://example.test".into()],
        body_bytes: 4096,
        concurrent: 3,
        anonymous_concurrent: 2,
        body_timeout: Duration::from_millis(20),
        request_timeout: Duration::from_millis(20),
        source: bucket(1000),
        session: bucket(1000),
    }
}
fn call() -> Call {
    Call::new(crate::Request::Challenge(ChallengeInput {
        publication: vec![1, 2, 3],
    }))
}
fn request(path: &str, body: impl Into<Body>) -> Request {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "api.example.test")
        .header(header::ORIGIN, "https://example.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}
async fn result(response: Response) -> ErrorCode {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    serde_json::from_slice::<Failure>(&bytes).unwrap().error
}

#[tokio::test]
async fn all_actions_are_registry_derived_and_no_authority_can_be_fabricated() {
    let app = router(limits()).unwrap();
    let ts = typescript();
    let spec = openapi();
    let info = actions();
    assert_eq!(info.len(), 21);
    for action in info {
        assert!(ts.contains(action.name));
        assert!((action.input_schema)().is_object());
        assert!(spec["paths"][format!("/v1/{}", action.name)]["post"].is_object());
    }
    let bytes = serde_json::to_vec(&call()).unwrap();
    let response = app
        .clone()
        .oneshot(request("/v1/challenge", bytes))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(result(response).await, ErrorCode::AuthorityUnavailable);
    for path in ["/unknown", "/v1/search"] {
        assert_eq!(
            result(
                app.clone()
                    .oneshot(request(path, serde_json::to_vec(&call()).unwrap()))
                    .await
                    .unwrap()
            )
            .await,
            ErrorCode::InvalidRequest
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result(response).await, ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn exact_origin_host_media_and_duplicate_header_checks_precede_body_work() {
    let app = router(limits()).unwrap();
    for (name, error) in [
        (header::HOST, ErrorCode::Host),
        (header::ORIGIN, ErrorCode::Origin),
        (header::CONTENT_TYPE, ErrorCode::MediaType),
    ] {
        for variant in 0..4 {
            let mut req = request("/v1/challenge", serde_json::to_vec(&call()).unwrap());
            match variant {
                0 => {
                    req.headers_mut().remove(&name);
                }
                1 => {
                    req.headers_mut()
                        .insert(&name, "https://foreign.test".parse().unwrap());
                }
                2 => {
                    let value = req.headers()[&name].clone();
                    req.headers_mut().append(&name, value);
                }
                _ => {
                    req.headers_mut()
                        .insert(&name, axum::http::HeaderValue::from_bytes(&[255]).unwrap());
                }
            }
            assert_eq!(result(app.clone().oneshot(req).await.unwrap()).await, error);
        }
    }
    let mut req = request("/v1/challenge", Body::empty());
    req.headers_mut().remove(header::HOST);
    req.headers_mut()
        .insert("x-forwarded-host", "api.example.test".parse().unwrap());
    assert_eq!(
        result(app.oneshot(req).await.unwrap()).await,
        ErrorCode::Host
    );
}

#[tokio::test]
async fn size_version_json_timeout_and_concurrency_are_bounded() {
    let app = router(limits()).unwrap();
    for (body,error) in [(vec![0;4097],ErrorCode::TooLarge),(b"bad".to_vec(),ErrorCode::InvalidRequest),
        (br#"{"version":2,"request":{"action":"challenge","input":{"publication":[]}}}"#.to_vec(),ErrorCode::UnsupportedVersion),
        (br#"{"version":1,"request":{"action":"challenge","input":{"publication":[],"extra":true}}}"#.to_vec(),ErrorCode::InvalidRequest),
        (br#"{"version":1,"version":1,"request":{"action":"challenge","input":{"publication":[]}}}"#.to_vec(),ErrorCode::InvalidRequest)] {
        assert_eq!(result(app.clone().oneshot(request("/v1/challenge",body)).await.unwrap()).await,error);
    }
    let pending = Body::from_stream(futures_util::stream::pending::<
        Result<Vec<u8>, std::io::Error>,
    >());
    assert_eq!(
        result(
            app.oneshot(request("/v1/challenge", pending))
                .await
                .unwrap()
        )
        .await,
        ErrorCode::Timeout
    );
    let mut config = Config::new(limits(), None, None).unwrap();
    config.anonymous = Semaphore::new(0);
    assert_eq!(
        result(
            handle(
                State(Arc::new(config)),
                request("/v1/challenge", Body::empty())
            )
            .await
        )
        .await,
        ErrorCode::Capacity
    );
    assert!(matches!(Call::decode(&[0; 5], 4), Err(ErrorCode::TooLarge)));
}

#[test]
fn configuration_rejects_ambiguous_or_missing_boundaries() {
    for mode in 0..14 {
        let mut value = limits();
        match mode {
            0 => value.hosts.clear(),
            1 => value.origins.clear(),
            2 => value.body_bytes = 0,
            3 => value.body_bytes = 1_048_577,
            4 => value.concurrent = 0,
            5 => value.concurrent = 4097,
            6 => value.body_timeout = Duration::ZERO,
            7 => value.anonymous_concurrent = 0,
            8 => value.anonymous_concurrent = value.concurrent,
            9 => value.request_timeout = Duration::ZERO,
            10 => value.source.burst = 0,
            11 => value.session.keys = 0,
            12 => value.source.replenish = Duration::ZERO,
            _ => value.hosts = vec!["%".into()],
        }
        assert!(router(value).is_err());
    }
    for host in [
        "",
        " ",
        "@",
        "user@api.example.test",
        "user:password@api.example.test",
        ":password@api.example.test",
        "api.example.test/path",
        "api.example.test?x=1",
        "api.example.test#fragment",
        "API.example.test",
        "api.example.test:443",
    ] {
        let mut value = limits();
        value.hosts = vec![host.into()];
        assert!(router(value).is_err());
    }
    for origin in [
        "bad",
        "http://example.test",
        "https://example.test/",
        "https://example.test/path",
    ] {
        let mut value = limits();
        value.origins = vec![origin.into()];
        assert!(router(value).is_err());
    }
}

struct RouterTransport(Router);
impl Transport for RouterTransport {
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        let response = self.0.clone().oneshot(request(path, body)).await.unwrap();
        Ok(to_bytes(response.into_body(), 4096)
            .await
            .map_err(|_| ErrorCode::Transport)?
            .to_vec())
    }
}
#[tokio::test]
async fn generated_rust_client_uses_real_http_refusal_without_domain_stubs() {
    let client = Client::new(RouterTransport(router(limits()).unwrap()), 4096);
    assert!(matches!(
        client.call(call().request).await,
        Err(ErrorCode::AuthorityUnavailable)
    ));
    let client = Client::new(RouterTransport(router(limits()).unwrap()), 1);
    assert!(matches!(
        client.call(call().request).await,
        Err(ErrorCode::TooLarge)
    ));
    assert_eq!(
        result(reject(ErrorCode::Transport)).await,
        ErrorCode::Transport
    );
    // Real malformed HTTP responses exercise transport failures without
    // inventing a successful domain implementation.
    let malformed = Router::new().route("/v1/challenge", post(|| async { "not-json" }));
    assert!(matches!(
        Client::new(RouterTransport(malformed), 4096)
            .call(call().request)
            .await,
        Err(ErrorCode::Transport)
    ));
    let oversized = Router::new().route("/v1/challenge", post(|| async { vec![0_u8; 4097] }));
    assert!(matches!(
        Client::new(RouterTransport(oversized), 4096)
            .call(call().request)
            .await,
        Err(ErrorCode::Transport)
    ));
}

#[tokio::test]
async fn browser_preflight_is_exact_scoped_and_does_not_share_credentials() {
    let app = router(limits()).unwrap();
    let preflight = || {
        Request::builder()
            .method("OPTIONS")
            .uri("/v1/challenge")
            .header(header::HOST, "api.example.test")
            .header(header::ORIGIN, "https://example.test")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type")
            .body(Body::empty())
            .unwrap()
    };
    let response = app.clone().oneshot(preflight()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://example.test"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "content-type"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );
    for (name, value, expected) in [
        (header::HOST, "foreign.test", ErrorCode::Host),
        (header::ORIGIN, "https://foreign.test", ErrorCode::Origin),
        (
            header::ACCESS_CONTROL_REQUEST_METHOD,
            "GET",
            ErrorCode::InvalidRequest,
        ),
        (
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "content-type, authorization",
            ErrorCode::InvalidRequest,
        ),
    ] {
        let mut req = preflight();
        req.headers_mut().insert(name, value.parse().unwrap());
        assert_eq!(
            result(app.clone().oneshot(req).await.unwrap()).await,
            expected
        );
    }
    for name in [
        header::ACCESS_CONTROL_REQUEST_METHOD,
        header::ACCESS_CONTROL_REQUEST_HEADERS,
    ] {
        for duplicate in [false, true] {
            let mut req = preflight();
            if duplicate {
                let value = req.headers()[&name].clone();
                req.headers_mut().append(&name, value);
            } else {
                req.headers_mut().remove(&name);
            }
            assert_eq!(
                result(app.clone().oneshot(req).await.unwrap()).await,
                ErrorCode::InvalidRequest
            );
        }
    }
    let response = app
        .oneshot(request(
            "/v1/challenge",
            serde_json::to_vec(&call()).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://example.test"
    );
    assert_eq!(response.headers()[header::VARY], "Origin");
    assert_eq!(result(response).await, ErrorCode::AuthorityUnavailable);
}

fn search(session: Vec<u8>) -> Call {
    Call::new(crate::Request::Search(SearchInput {
        possession: Possession {
            session,
            request_nonce: vec![1],
            signature: vec![2],
        },
        cursor: None,
        page_size: 1,
    }))
}
fn from(request: Request, address: &str) -> Request {
    let mut request = request;
    request
        .extensions_mut()
        .insert(ConnectInfo(address.parse::<SocketAddr>().unwrap()));
    request
}

#[test]
fn sources_are_normalised_before_they_select_a_bucket() {
    let key = |address: Option<&str>| {
        let mut req = request("/v1/challenge", Body::empty());
        if let Some(address) = address {
            req = from(req, address);
        }
        source(&req)
    };
    assert_eq!(key(None), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(
        key(Some("192.0.2.7:1")),
        "192.0.2.7".parse::<IpAddr>().unwrap()
    );
    assert_eq!(key(Some("[::ffff:192.0.2.7]:1")), key(Some("192.0.2.7:9")));
    // Every address of one IPv6 /64 shares a bucket; another /64 does not.
    assert_eq!(
        key(Some("[2001:db8:1:2::1]:1")),
        key(Some("[2001:db8:1:2:ffff::9]:2"))
    );
    assert_ne!(
        key(Some("[2001:db8:1:2::1]:1")),
        key(Some("[2001:db8:1:3::1]:1"))
    );
}

#[tokio::test]
async fn one_source_cannot_exhaust_the_others_and_is_limited_before_any_work() {
    let mut value = limits();
    value.source = Bucket {
        burst: 1,
        replenish: Duration::from_secs(3600),
        keys: 4,
    };
    let app = router(value).unwrap();
    let body = serde_json::to_vec(&call()).unwrap();
    let send = |address: &'static str| {
        let app = app.clone();
        let body = body.clone();
        async move {
            result(
                app.oneshot(from(request("/v1/challenge", body), address))
                    .await
                    .unwrap(),
            )
            .await
        }
    };
    assert_eq!(send("192.0.2.1:1").await, ErrorCode::AuthorityUnavailable);
    assert_eq!(send("192.0.2.1:2").await, ErrorCode::Capacity);
    assert_eq!(send("192.0.2.2:1").await, ErrorCode::AuthorityUnavailable);
}

#[tokio::test]
async fn anonymous_and_authenticated_capacity_are_separate_pools() {
    let mut config = Config::new(limits(), None, None).unwrap();
    config.authenticated = Semaphore::new(0);
    let config = Arc::new(config);
    // Authenticated actions are refused while pre-session actions still run.
    let body = serde_json::to_vec(&search(vec![1; 16])).unwrap();
    assert_eq!(
        result(handle(State(config.clone()), request("/v1/search", body)).await).await,
        ErrorCode::Capacity
    );
    let body = serde_json::to_vec(&call()).unwrap();
    assert_eq!(
        result(handle(State(config.clone()), request("/v1/challenge", body)).await).await,
        ErrorCode::AuthorityUnavailable
    );
    let mut config = Config::new(limits(), None, None).unwrap();
    config.anonymous = Semaphore::new(0);
    let body = serde_json::to_vec(&search(vec![1; 16])).unwrap();
    assert_eq!(
        result(handle(State(Arc::new(config)), request("/v1/search", body)).await).await,
        ErrorCode::AuthorityUnavailable
    );
}

#[tokio::test]
async fn one_session_cannot_create_unbounded_replay_state() {
    let mut value = limits();
    value.session = Bucket {
        burst: 2,
        replenish: Duration::from_secs(3600),
        keys: 4,
    };
    let app = router(value).unwrap();
    let send = |session: Vec<u8>| {
        let app = app.clone();
        async move {
            let body = serde_json::to_vec(&search(session)).unwrap();
            result(app.oneshot(request("/v1/search", body)).await.unwrap()).await
        }
    };
    assert_eq!(send(vec![1; 16]).await, ErrorCode::AuthorityUnavailable);
    assert_eq!(send(vec![1; 16]).await, ErrorCode::AuthorityUnavailable);
    assert_eq!(send(vec![1; 16]).await, ErrorCode::Capacity);
    assert_eq!(send(vec![2; 16]).await, ErrorCode::AuthorityUnavailable);
    assert_eq!(
        send(vec![3; SESSION_BYTES + 1]).await,
        ErrorCode::InvalidRequest
    );
}

#[tokio::test]
async fn a_stalled_owner_times_out_instead_of_holding_the_request() {
    let (controller, _owner) = crate::runtime::Handle::stalled();
    let app = router_with(limits(), controller).unwrap();
    let body = serde_json::to_vec(&call()).unwrap();
    let response = app.oneshot(request("/v1/challenge", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(result(response).await, ErrorCode::Timeout);
}

#[tokio::test]
async fn idle_source_and_session_keys_are_dropped_on_a_timer_until_the_router_ends() {
    let mut value = limits();
    value.source = Bucket {
        burst: 1,
        replenish: Duration::from_millis(2),
        keys: 8,
    };
    value.session = value.source;
    let config = Arc::new(Config::new(value, None, None).unwrap());
    assert!(config.source.admit(&"192.0.2.1".parse().unwrap()));
    assert!(config.session.admit(&vec![1]));
    assert_eq!((config.source.tracked(), config.session.tracked()), (1, 1));
    spawn_pruner(&config, Duration::from_millis(10));
    for _ in 0..100 {
        if config.source.tracked() + config.session.tracked() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!((config.source.tracked(), config.session.tracked()), (0, 0));
    // The pruner ends once the configuration is gone.
    let weak = Arc::downgrade(&config);
    drop(config);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn a_full_source_table_throttles_new_sources_together_instead_of_locking_out() {
    let mut value = limits();
    value.source = Bucket {
        burst: 1,
        replenish: Duration::from_secs(3600),
        keys: 1,
    };
    let app = router(value).unwrap();
    let body = serde_json::to_vec(&call()).unwrap();
    let send = |address: &'static str| {
        let app = app.clone();
        let body = body.clone();
        async move {
            result(
                app.oneshot(from(request("/v1/challenge", body), address))
                    .await
                    .unwrap(),
            )
            .await
        }
    };
    // The attacker's address fills the one-key table and is then limited.
    assert_eq!(send("192.0.2.1:1").await, ErrorCode::AuthorityUnavailable);
    assert_eq!(send("192.0.2.1:2").await, ErrorCode::Capacity);
    // A legitimate new source still passes once at the shared overflow rate;
    // further new sources are throttled together.
    assert_eq!(send("192.0.2.2:1").await, ErrorCode::AuthorityUnavailable);
    assert_eq!(send("192.0.2.3:1").await, ErrorCode::Capacity);
}

#[tokio::test]
async fn communities_are_resolved_from_the_registry_per_request() {
    use crate::tenant::tests as fixtures;
    let (registry, _, tenants) = fixtures::setup(Duration::from_secs(60), 4);
    fixtures::put(
        &registry,
        "one.example.test",
        fixtures::record(fixtures::A, crate::tenant::State::Live),
    );
    let mut dynamic = limits();
    let (_, _, other) = fixtures::setup(Duration::from_secs(1), 1);
    assert!(router_tenants(limits(), Arc::new(other)).is_err());
    dynamic.hosts.clear();
    dynamic.origins.clear();
    let app = router_tenants(dynamic, Arc::new(tenants)).unwrap();
    let call = |host: &str, origin: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/challenge")
            .header(header::HOST, host)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&call()).unwrap()))
            .unwrap()
    };
    let unknown = app
        .clone()
        .oneshot(call("two.example.test", "https://01234567.example.test"))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::MISDIRECTED_REQUEST);
    let wrong = app
        .clone()
        .oneshot(call("one.example.test", "https://example.test"))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    // The community's owner is reached (the fake owner never answers).
    let reached = app
        .clone()
        .oneshot(call("one.example.test", "https://01234567.example.test"))
        .await
        .unwrap();
    assert_eq!(reached.status(), StatusCode::REQUEST_TIMEOUT);
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/v1/challenge")
        .header(header::HOST, "one.example.test")
        .header(header::ORIGIN, "https://01234567.example.test")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(preflight).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let two_hosts = Request::builder()
        .method("POST")
        .uri("/v1/challenge")
        .header(header::HOST, "one.example.test")
        .header(header::HOST, "two.example.test")
        .header(header::ORIGIN, "https://01234567.example.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(two_hosts).await.unwrap().status(),
        StatusCode::MISDIRECTED_REQUEST
    );
}
