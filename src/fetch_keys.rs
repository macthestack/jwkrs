use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde::Deserialize;
use std::time::Duration;

use crate::get_max_age::get_max_age;
use crate::jwk_auth::JwkKey;
use crate::JwkConfiguration;

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<JwkKey>,
}

const FALLBACK_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
#[allow(dead_code)]
pub enum GetKeysError {
    RequestFailed(reqwest::Error),
    ParsingFailed(reqwest::Error),
    NotModified(Duration),
}

pub async fn get_keys(
    config: &JwkConfiguration,
    client: &reqwest::Client,
    etag: Option<&str>,
) -> Result<(Vec<JwkKey>, Duration, Option<String>), GetKeysError> {
    let mut request = client.get(&config.jwk_url);
    if let Some(etag_value) = etag {
        request = request.header(IF_NONE_MATCH, etag_value);
    }

    let http_response = request.send().await.map_err(GetKeysError::RequestFailed)?;

    match http_response.status() {
        reqwest::StatusCode::NOT_MODIFIED => {
            let duration = get_max_age(&http_response).unwrap_or(FALLBACK_TIMEOUT);
            Err(GetKeysError::NotModified(duration))
        }
        reqwest::StatusCode::OK => {
            let duration = get_max_age(&http_response).unwrap_or(FALLBACK_TIMEOUT);
            let new_etag = http_response
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let result = http_response
                .json::<KeyResponse>()
                .await
                .map_err(GetKeysError::ParsingFailed)?;
            Ok((result.keys, duration, new_etag))
        }
        _ => Err(GetKeysError::RequestFailed(
            http_response.error_for_status().unwrap_err(),
        )),
    }
}
