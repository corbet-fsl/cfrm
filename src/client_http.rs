//! Maintained native HTTPS with no ambient identity or automatic effect retry.
use crate::{ErrorCode, Transport, endpoint::Endpoint};
pub struct HttpTransport {
    endpoint: Endpoint,
    client: reqwest::Client,
}
impl HttpTransport {
    pub fn new(
        forum_origin: String,
        member_origin: String,
        maximum_response: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, ErrorCode> {
        Self::with_roots(forum_origin, member_origin, maximum_response, timeout, &[])
    }
    /// The same with extra trusted root certificates (DER) added to the public root store.
    /// Deployment configuration only (private test stacks); production passes none.
    pub fn with_roots(
        forum_origin: String,
        member_origin: String,
        maximum_response: usize,
        timeout: std::time::Duration,
        roots: &[Vec<u8>],
    ) -> Result<Self, ErrorCode> {
        let endpoint = Endpoint::new(forum_origin, member_origin, maximum_response, timeout)?;
        let mut builder = reqwest::Client::builder();
        for root in roots {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_der(root).map_err(|_| ErrorCode::InvalidRequest)?,
            );
        }
        let client = builder
            .user_agent("cfrm-client")
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(endpoint.timeout)
            .build()
            .map_err(|_| ErrorCode::Transport)?;
        Ok(Self { endpoint, client })
    }
}
impl Transport for HttpTransport {
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        let target = self.endpoint.target(path, &body)?;
        let request = self
            .client
            .post(target)
            .header("origin", &self.endpoint.member)
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .body(body)
            .build()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        if response.status().is_redirection()
            || response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                != Some("application/json")
            || response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                != Some("no-store")
            || response
                .content_length()
                .is_some_and(|size| size > self.endpoint.maximum as u64)
        {
            return Err(ErrorCode::Reconcile);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ErrorCode::Reconcile)? {
            if chunk.len() > self.endpoint.maximum - bytes.len() {
                return Err(ErrorCode::Reconcile);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
