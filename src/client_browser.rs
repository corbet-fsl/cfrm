//! Bounded Fetch/Web Streams via maintained browser bindings. No cookies,
//! redirects, referrers, cached responses or automatic request retries.
use crate::{ErrorCode, Transport, endpoint::Endpoint};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
pub struct BrowserTransport {
    endpoint: Endpoint,
}
impl BrowserTransport {
    pub fn new(
        forum_origin: String,
        member_origin: String,
        maximum_response: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, ErrorCode> {
        Ok(Self {
            endpoint: Endpoint::new(forum_origin, member_origin, maximum_response, timeout)?,
        })
    }
}
struct Cancel(web_sys::AbortController);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Transport for BrowserTransport {
    async fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
        let target = self.endpoint.target(path, &body)?;
        let window = web_sys::window().ok_or(ErrorCode::Transport)?;
        if window.location().origin().map_err(|_| ErrorCode::Origin)? != self.endpoint.member {
            return Err(ErrorCode::Origin);
        }
        let headers = web_sys::Headers::new().map_err(|_| ErrorCode::Transport)?;
        headers
            .set("content-type", "application/json")
            .map_err(|_| ErrorCode::Transport)?;
        let controller = web_sys::AbortController::new().map_err(|_| ErrorCode::Transport)?;
        let cancel = Cancel(controller.clone());
        let _timeout = gloo_timers::callback::Timeout::new(
            self.endpoint.timeout.as_millis() as u32,
            move || controller.abort(),
        );
        let options = web_sys::RequestInit::new();
        options.set_method("POST");
        options.set_mode(web_sys::RequestMode::Cors);
        options.set_headers(&headers);
        options.set_redirect(web_sys::RequestRedirect::Error);
        options.set_credentials(web_sys::RequestCredentials::Omit);
        options.set_cache(web_sys::RequestCache::NoStore);
        options.set_referrer_policy(web_sys::ReferrerPolicy::NoReferrer);
        options.set_signal(Some(&cancel.0.signal()));
        options.set_body(&js_sys::Uint8Array::from(body.as_slice()).into());
        let request = web_sys::Request::new_with_str_and_init(&target, &options)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| ErrorCode::Reconcile)?
            .dyn_into::<web_sys::Response>()
            .map_err(|_| ErrorCode::Reconcile)?;
        if response.redirected()
            || response
                .headers()
                .get("content-type")
                .map_err(|_| ErrorCode::Reconcile)?
                .as_deref()
                != Some("application/json")
            || response
                .headers()
                .get("cache-control")
                .map_err(|_| ErrorCode::Reconcile)?
                .as_deref()
                != Some("no-store")
            || response
                .headers()
                .get("content-length")
                .map_err(|_| ErrorCode::Reconcile)?
                .is_some_and(|value| {
                    value
                        .parse::<u64>()
                        .is_ok_and(|size| size > self.endpoint.maximum as u64)
                })
        {
            return Err(ErrorCode::Reconcile);
        }
        let reader = response
            .body()
            .ok_or(ErrorCode::Reconcile)?
            .get_reader()
            .dyn_into::<web_sys::ReadableStreamDefaultReader>()
            .map_err(|_| ErrorCode::Reconcile)?;
        let mut bytes = Vec::new();
        loop {
            let next = JsFuture::from(reader.read())
                .await
                .map_err(|_| ErrorCode::Reconcile)?;
            let done = js_sys::Reflect::get(&next, &"done".into())
                .map_err(|_| ErrorCode::Reconcile)?
                .as_bool()
                .ok_or(ErrorCode::Reconcile)?;
            if done {
                break;
            }
            let chunk = js_sys::Reflect::get(&next, &"value".into())
                .map_err(|_| ErrorCode::Reconcile)?
                .dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| ErrorCode::Reconcile)?;
            if chunk.length() as usize > self.endpoint.maximum - bytes.len() {
                return Err(ErrorCode::Reconcile);
            }
            bytes.extend_from_slice(&chunk.to_vec());
        }
        Ok(bytes)
    }
}
