mod auth;

use auth::{Authentication, Header};
use axum::{handler::get, AddExtensionLayer, Router};
use jwkrs::config::JwkConfiguration;
use std::net::SocketAddr;
use std::collections::HashSet;

#[tokio::main]
async fn main() {
    let config = JwkConfiguration {
        jwk_url: "{JWK_URL}".to_string(),
        audience: "{AUDIENCE}".to_string(),
        issuers: HashSet::from(["{ISSUER}".to_string()]),
    };
    let jwk = jwkrs::JwkAuth::new(config);
    let app = Router::new()
        .route("/", get(root))
        .layer(AddExtensionLayer::new(jwk));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
async fn root(auth: Authentication<Header>) -> String {
    format!("User Id: {:?}", auth.sub)
}
