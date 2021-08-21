use jsonwebtoken::TokenData;
use std::sync::Arc;
use std::time::Duration;
use tokio::{sync::RwLock, time::sleep};

use crate::{
    fetch_keys::fetch_keys,
    verifier::{Claims, JwkVerifier},
};
#[derive(Clone)]
pub struct JwkAuth {
    config: JwkConfiguration,
    verifier: Arc<RwLock<JwkVerifier>>,
}

#[derive(Clone, Debug)]
pub struct JwkConfiguration {
    pub url: String,
    pub audience: String,
    pub issuer: String,
}

impl JwkAuth {
    pub async fn new(url: String, audience: String, issuer: String) -> JwkAuth {
        let config = JwkConfiguration {
            url,
            audience,
            issuer,
        };
        let verifier = Arc::new(RwLock::new(JwkVerifier::new(config.clone())));

        let mut instance = JwkAuth { verifier, config };

        instance.start_key_update();
        instance
    }
    pub async fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = self.verifier.read().await;
        verifier.verify(token)
    }

    fn start_key_update(&mut self) {
        let verifier_ref = Arc::clone(&self.verifier);
        let config = self.config.clone();
        tokio::spawn(async move {
            loop {
                let keys_o = fetch_keys(&config).await.ok();

                match keys_o {
                    Some(keys) => {
                        {
                            let mut verifier = verifier_ref.write().await;
                            verifier.set_keys(keys.keys);
                        } // Drop write lock.

                        sleep(keys.validity).await
                    }
                    None => {
                        eprintln!("Couldn't fetch jwk.");
                        sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        });
    }
}
