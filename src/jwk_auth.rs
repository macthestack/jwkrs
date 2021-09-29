use crate::config::JwkConfiguration;
use crate::fetch_keys::get_keys;
use crate::verifier::{Claims, JwkVerifier};
use evmap::{ReadHandleFactory, WriteHandle};
use evmap_derive::ShallowCopy;
use jsonwebtoken::TokenData;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone)]
pub struct JwkAuth {
    keys: ReadHandleFactory<String, JwkKey>,
    config: JwkConfiguration,
}

#[derive(Clone, Default, Debug, Deserialize, Eq, PartialEq, Hash, ShallowCopy)]
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
            keys: r.factory(),
            config: config.clone(),
        };

        tokio::spawn(key_update(config, w));

        instance
    }

    pub async fn verify(self, token: &String) -> Option<TokenData<Claims>> {
        let verifier = JwkVerifier {
            keys: &self.keys,
            config: &self.config,
        };

        verifier.verify(token)
    }
}

async fn key_update<'a>(config: JwkConfiguration, mut w: WriteHandle<String, JwkKey>) {
    loop {
        let keys = get_keys(&config).await;
        let duration = match keys {
            Ok((keys, duration)) => {
                println!("Duration: {:?}", duration);
                for k in keys {
                    w.update(k.kid.clone(), k);
                }
                w.refresh();
                duration
            }
            Err(_) => Duration::from_secs(10),
        };
        sleep(duration).await;
    }
}
