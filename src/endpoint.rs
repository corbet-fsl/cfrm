use crate::{ErrorCode, actions};
pub(crate) struct Endpoint {
    pub forum: String,
    pub member: String,
    pub maximum: usize,
    /// Only the direct transports enforce it; the OHTTP wire owns its own timeout.
    #[cfg_attr(feature = "client-ohttp", allow(dead_code))]
    pub timeout: std::time::Duration,
}
impl Endpoint {
    pub fn new(
        forum: String,
        member: String,
        maximum: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, ErrorCode> {
        for origin in [&forum, &member] {
            let url = url::Url::parse(origin).map_err(|_| ErrorCode::Origin)?;
            if url.scheme() != "https" || url.origin().ascii_serialization() != *origin {
                return Err(ErrorCode::Origin);
            }
        }
        if maximum == 0
            || maximum > 16 * 1024 * 1024
            || timeout.is_zero()
            || timeout.as_millis() > u32::MAX.into()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            forum,
            member,
            maximum,
            timeout,
        })
    }
    pub fn target(&self, path: &str, body: &[u8]) -> Result<String, ErrorCode> {
        if body.len() > 1_048_576 {
            return Err(ErrorCode::TooLarge);
        }
        if !actions()
            .iter()
            .any(|action| path == format!("/v1/{}", action.name))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(format!("{}{path}", self.forum))
    }
}
