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
    verifier: Arc<RwLock<JwkVerifier>>,
}

impl JwkAuth {
    pub async fn new() -> JwkAuth {
        let verifier = Arc::new(RwLock::new(JwkVerifier::new()));

        let mut instance = JwkAuth { verifier };

        instance.start_key_update();
        instance
    }

    pub async fn verify(&self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = self.verifier.read().await;
        verifier.verify(token)
    }

    fn start_key_update(&mut self) {
        let verifier_ref = Arc::clone(&self.verifier);

        tokio::spawn(async move {
            loop {
                let keys_o = fetch_keys().await.ok();

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
