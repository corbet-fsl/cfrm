//! Registry client. Wire contract (JSON over HTTPS, read-only):
//! `GET <url>/by-host?host=<host>` answers 200 with one community record or
//! 404; `GET <url>/finished` answers 200 with the identifiers (32 hex digits)
//! of every community that is ending or ended. The registry decides what the
//! forum trusts about a community, so the URL must be a trusted internal
//! endpoint of the platform.
use cfrm::{
    ErrorCode,
    tenant::{Directory, Fut, Record},
};
use reqwest::{StatusCode, redirect::Policy};
use serde::Deserialize;
use std::time::Duration;

const MAXIMUM_BYTES: usize = 262_144;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub url: String,
    pub timeout_ms: u64,
    /// How long a registry answer is used. An ended community stops being served
    /// within this time.
    pub recheck_seconds: u64,
    /// How often the registry's list of finished communities is read.
    pub sweep_seconds: u64,
    /// Upper bound on communities running in this process.
    pub maximum_communities: usize,
}

pub struct Http {
    client: reqwest::Client,
    url: url::Url,
}
impl Http {
    pub fn new(configuration: &Configuration) -> Result<Self, ErrorCode> {
        let url = url::Url::parse(&configuration.url).map_err(|_| ErrorCode::InvalidRequest)?;
        let local = matches!(url.host(), Some(url::Host::Domain("localhost")))
            || matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
            || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
        if !(url.scheme() == "https" || (url.scheme() == "http" && local))
            || url.query().is_some()
            || url.fragment().is_some()
            || configuration.timeout_ms == 0
            || configuration.recheck_seconds == 0
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(configuration.timeout_ms))
            .redirect(Policy::none())
            .build()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        Ok(Self { client, url })
    }
    fn endpoint(&self, name: &str) -> url::Url {
        let mut url = self.url.clone();
        url.path_segments_mut()
            .expect("hierarchical URL")
            .pop_if_empty()
            .push(name);
        url
    }
    async fn get(&self, url: url::Url) -> Result<Option<Vec<u8>>, ErrorCode> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        match response.status() {
            StatusCode::NOT_FOUND => return Ok(None),
            StatusCode::OK => {}
            _ => return Err(ErrorCode::AuthorityUnavailable),
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_BYTES as u64)
        {
            return Err(ErrorCode::TooLarge);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        if bytes.len() > MAXIMUM_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        Ok(Some(bytes.to_vec()))
    }
}
impl Directory for Http {
    fn by_host(&self, host: &str) -> Fut<'_, Result<Option<Record>, ErrorCode>> {
        let mut url = self.endpoint("by-host");
        url.query_pairs_mut().append_pair("host", host);
        Box::pin(async move {
            match self.get(url).await? {
                None => Ok(None),
                Some(bytes) => serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|_| ErrorCode::AuthorityUnavailable),
            }
        })
    }
    fn finished(&self) -> Fut<'_, Result<Vec<String>, ErrorCode>> {
        let url = self.endpoint("finished");
        Box::pin(async move {
            match self.get(url).await? {
                None => Ok(Vec::new()),
                Some(bytes) => {
                    serde_json::from_slice(&bytes).map_err(|_| ErrorCode::AuthorityUnavailable)
                }
            }
        })
    }
}
