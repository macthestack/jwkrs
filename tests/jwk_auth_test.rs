use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use jwkrs::{Audience, Claims, JwkAuth, JwkConfiguration, JwkKey};
use rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::iter::FromIterator;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Serialize, Deserialize)]
struct KeyResponse {
    keys: Vec<JwkKey>,
}

fn biguint_to_base64url(biguint: &BigUint) -> String {
    let bytes = biguint.to_bytes_be();
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn public_key_to_jwk(public_key: &RsaPublicKey, kid: String) -> JwkKey {
    let n = biguint_to_base64url(&public_key.n());
    let e = biguint_to_base64url(&public_key.e());
    JwkKey {
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        kid: kid,
        n: n,
        e: e,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_jwk_auth_end_to_end() {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);

    let kid = "test_key".to_string();
    let jwk = public_key_to_jwk(&public_key, kid.clone());

    let mock_server = MockServer::start().await;
    let jwk_set = serde_json::to_string(&KeyResponse { keys: vec![jwk] }).unwrap();
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(jwk_set)
                .insert_header("Cache-Control", "max-age=3600")
                .insert_header("ETag", "v1"),
        )
        .mount(&mock_server)
        .await;

    let config = JwkConfiguration {
        jwk_url: mock_server.uri(),
        audience: "test_audience".to_string(),
        issuers: HashSet::from_iter(vec!["test_issuer".to_string()]),
    };
    let auth = JwkAuth::new(config);

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let handle = auth.validators.handle();
            if handle.contains_key(&kid) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Timeout waiting for keys to load");

    let claims = Claims {
        aud: Audience::Single("test_audience".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
        iss: "test_issuer".to_string(),
        sub: "test_subject".to_string(),
        iat: Utc::now().timestamp(),
    };
    let private_key_pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("Failed to encode private key to PEM");
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to create encoding key");
    let header = Header {
        kid: Some(kid.clone()),
        alg: jsonwebtoken::Algorithm::RS256,
        ..Default::default()
    };
    let token = encode(&header, &claims, &encoding_key).expect("Failed to encode token");

    let token_data = auth
        .verify(&token)
        .await
        .expect("Token verification failed");

    assert_eq!(token_data.claims.sub, "test_subject");
    assert_eq!(token_data.claims.iss, "test_issuer");
    assert_eq!(
        token_data.claims.aud,
        Audience::Single("test_audience".to_string())
    );
}
