use serde::Deserialize;
use std::time::Duration;
use tracing::error;

use crate::config::JwkConfiguration;
use crate::get_max_age::get_max_age;
use crate::jwk_auth::JwkKey;

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<JwkKey>,
}

const FALLBACK_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn get_keys(config: &JwkConfiguration) -> Result<(Vec<JwkKey>, Duration), ()> {
    let http_response = reqwest::get(config.jwk_url.clone()).await.map_err(|_| {
        error!("Failed to fetch keys from {}", config.jwk_url);
        ()
    })?;
    let max_age = get_max_age(&http_response).unwrap_or(FALLBACK_TIMEOUT);
    let result = http_response.json::<KeyResponse>().await.map_err(|_| {
        error!("Failed to parse keys from {}", config.jwk_url);
        ()
    })?;

    return Ok((result.keys, max_age));
}
