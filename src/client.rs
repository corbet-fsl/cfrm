use crate::{Call, ErrorCode, Failure, Request};
use std::future::Future;

/// The member runtime supplies HTTPS transport. No fallback to an alternate
/// origin or direct peer networking is part of this client.
pub trait Transport {
    fn post(&self, path: &str, body: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, ErrorCode>>;
}

pub struct Client<T> {
    transport: T,
    maximum_response: usize,
}
impl<T: Transport> Client<T> {
    pub fn new(transport: T, maximum_response: usize) -> Self {
        Self {
            transport,
            maximum_response,
        }
    }

    /// All server actions currently fail closed; no fabricated success body is
    /// parsed. A future success response must be added in the same registry.
    pub async fn call(&self, request: Request) -> Result<std::convert::Infallible, ErrorCode> {
        let path = format!("/v1/{}", request.info().name);
        let body =
            serde_json::to_vec(&Call::new(request)).map_err(|_| ErrorCode::InvalidRequest)?;
        let bytes = self.transport.post(&path, body).await?;
        if bytes.len() > self.maximum_response {
            return Err(ErrorCode::TooLarge);
        }
        let failure: Failure = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Transport)?;
        Err(failure.error)
    }
}
