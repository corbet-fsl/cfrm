//! Forum transport through Oblivious HTTP: the relay sees the sender but only
//! ciphertext, the gateway sees the call but not the sender.
use crate::{ErrorCode, Transport, actions, endpoint::Endpoint};
use ohttp_lib::{Lane, client::Wire, codec};
use std::time::Duration;

pub struct OhttpTransport<W> {
    wire: W,
    endpoint: Endpoint,
    authority: String,
}

impl<W: Wire> OhttpTransport<W> {
    pub fn new(
        wire: W,
        forum_origin: String,
        member_origin: String,
        maximum_response: usize,
        timeout: Duration,
    ) -> Result<Self, ErrorCode> {
        let endpoint = Endpoint::new(forum_origin, member_origin, maximum_response, timeout)?;
        let url = url::Url::parse(&endpoint.forum).map_err(|_| ErrorCode::Origin)?;
        let host = url.host_str().ok_or(ErrorCode::Origin)?;
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        Ok(Self { wire, endpoint, authority })
    }
}

fn lane(path: &str) -> Lane {
    let anonymous = path.strip_prefix("/v1/").is_some_and(|name| {
        actions()
            .iter()
            .any(|action| action.name == name && action.requirement != crate::Requirement::CurrentDeviceSession)
    });
    if anonymous { Lane::Anonymous } else { Lane::Session }
}

impl<W: Wire> Transport for OhttpTransport<W> {
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        // Validates the action path and the body size exactly as the direct transports do.
        self.endpoint.target(path, &body)?;
        let request = codec::Request {
            method: b"POST".to_vec(),
            authority: self.authority.clone().into_bytes(),
            path: path.as_bytes().to_vec(),
            headers: vec![
                (b"origin".to_vec(), self.endpoint.member.clone().into_bytes()),
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"cache-control".to_vec(), b"no-store".to_vec()),
            ],
            body,
        };
        let response = self
            .wire
            .exchange(lane(path), request)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        let header = |name: &[u8]| {
            response
                .headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_slice())
        };
        if header(b"content-type") != Some(&b"application/json"[..])
            || header(b"cache-control") != Some(&b"no-store"[..])
            || response.body.len() > self.endpoint.maximum
        {
            return Err(ErrorCode::Reconcile);
        }
        Ok(response.body)
    }
}
