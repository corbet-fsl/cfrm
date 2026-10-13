use crate::{Call, ErrorCode, Failure, Reply, Request};
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

    /// Decode only the registry's exact versioned response for this action.
    /// Transport success alone never becomes a successful domain response.
    pub async fn call(&self, request: Request) -> Result<Reply, ErrorCode> {
        let action = request.info().name;
        let path = format!("/v1/{}", request.info().name);
        let body =
            serde_json::to_vec(&Call::new(request)).map_err(|_| ErrorCode::InvalidRequest)?;
        let bytes = self.transport.post(&path, body).await?;
        if bytes.len() > self.maximum_response {
            return Err(ErrorCode::TooLarge);
        }
        if let Ok(failure) = serde_json::from_slice::<Failure>(&bytes) {
            return Err(failure.error);
        }
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Transport)?;
        if reply.version != 1 || reply.response.action() != action {
            return Err(ErrorCode::Transport);
        }
        Ok(reply)
    }
}
