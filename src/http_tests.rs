use super::*;
use crate::*;
use axum::{body::Body, extract::Request};
use tower::ServiceExt;

fn limits() -> Limits {
    Limits {
        hosts: vec!["api.example.test".into()],
        origins: vec!["https://example.test".into()],
        body_bytes: 4096,
        concurrent: 2,
        body_timeout: Duration::from_millis(20),
    }
}
fn call() -> Call {
    Call::new(crate::Request::Challenge(ChallengeInput {
        credential: vec![1, 2, 3],
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
    assert_eq!(info.len(), 12);
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
        (br#"{"version":2,"request":{"action":"challenge","input":{"credential":[]}}}"#.to_vec(),ErrorCode::UnsupportedVersion),
        (br#"{"version":1,"request":{"action":"challenge","input":{"credential":[],"extra":true}}}"#.to_vec(),ErrorCode::InvalidRequest),
        (br#"{"version":1,"version":1,"request":{"action":"challenge","input":{"credential":[]}}}"#.to_vec(),ErrorCode::InvalidRequest)] {
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
    let config = Arc::new(Config {
        limits: limits(),
        concurrent: Semaphore::new(0),
    });
    assert_eq!(
        result(handle(State(config), request("/v1/challenge", Body::empty())).await).await,
        ErrorCode::Capacity
    );
    assert!(matches!(Call::decode(&[0; 5], 4), Err(ErrorCode::TooLarge)));
}

#[test]
fn configuration_rejects_ambiguous_or_missing_boundaries() {
    for mode in 0..8 {
        let mut value = limits();
        match mode {
            0 => value.hosts.clear(),
            1 => value.origins.clear(),
            2 => value.body_bytes = 0,
            3 => value.body_bytes = 1_048_577,
            4 => value.concurrent = 0,
            5 => value.concurrent = 4097,
            6 => value.body_timeout = Duration::ZERO,
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
