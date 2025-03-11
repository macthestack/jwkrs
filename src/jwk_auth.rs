use crate::config::JwkConfiguration;
use crate::fetch_keys::{get_keys, GetKeysError};
use crate::key::Key;
use crate::verifier::{Claims, JwkVerifier};
use evmap::{ReadHandleFactory, WriteHandle};
use evmap_derive::ShallowCopy;
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::fmt::Debug;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error};

#[derive(Clone)]
pub struct JwkAuth {
    pub validators: ReadHandleFactory<String, Key>,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize, Eq, PartialEq, Hash, ShallowCopy)]
pub struct JwkKey {
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub kid: String,
    pub n: String,
}

impl JwkAuth {
    pub fn new(config: JwkConfiguration) -> JwkAuth {
        let (r, w) = evmap::new();

        let instance = JwkAuth {
            validators: r.factory(),
        };

        tokio::spawn(key_update(config, w));

        instance
    }

    pub async fn verify(&self, token: &str) -> Option<TokenData<Claims>> {
        let verifier = JwkVerifier {
            validators: &self.validators,
        };

        let verification_result = verifier.verify(token);

        match verification_result {
            Ok(token_data) => Some(token_data),
            Err(e) => {
                debug!("Token verification failed: {:?}", e);
                None
            }
        }
    }
}

async fn key_update(config: JwkConfiguration, mut w: WriteHandle<String, Key>) {
    let client = reqwest::Client::new();
    let mut etag: Option<String> = None;
    let mut retry_delay = Duration::from_secs(10);
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(600); // 10 minutes
    const MIN_REFRESH_DURATION: Duration = Duration::from_secs(300); // 5 minutes
    const MAX_REFRESH_DURATION: Duration = Duration::from_secs(86400); // 1 day

    loop {
        match get_keys(&config, &client, etag.as_deref()).await {
            Ok((keys, duration, new_etag)) => {
                retry_delay = Duration::from_secs(10);
                etag = new_etag;

                w.purge();
                for key in keys {
                    match Key::from_jwk_key(&key, &config) {
                        Ok(validator) => {
                            w.update(key.kid.clone(), validator);
                        }
                        Err(e) => {
                            error!("Failed to create validator for key ID {}: {:?}", key.kid, e);
                        }
                    }
                }
                w.refresh();

                let next_refresh = duration.clamp(MIN_REFRESH_DURATION, MAX_REFRESH_DURATION);

                sleep(next_refresh).await;
            }
            Err(GetKeysError::NotModified(duration)) => {
                let next_refresh = duration.clamp(MIN_REFRESH_DURATION, MAX_REFRESH_DURATION);
                sleep(next_refresh).await;
            }
            Err(_) => {
                error!("Failed to fetch keys");

                sleep(retry_delay).await;

                retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY);
            }
        }
    }
}
