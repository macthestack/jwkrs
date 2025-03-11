mod auth;

use auth::{Authentication, Header};
use axum::routing::get;
use axum::{Extension, Router, debug_handler};
use jwkrs::JwkConfiguration;
use std::collections::HashSet;

#[tokio::main]
async fn main() {
    let config = JwkConfiguration {
        jwk_url: "{JWK_URL}".to_string(), // Replace with your actual JWK URL
        audience: "{AUDIENCE}".to_string(), // Replace with your audience
        issuers: HashSet::from(["{ISSUER}".to_string()]), // Replace with your issuer
    };
    let jwk = jwkrs::JwkAuth::new(config);
    let app = Router::new()
        .route("/", get(root))
        .layer(Extension(jwk.clone()));

    println!("Listening on 3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[debug_handler]
async fn root(auth: Authentication<Header>) -> String {
    format!("User Id: {:?}", auth.sub)
}
