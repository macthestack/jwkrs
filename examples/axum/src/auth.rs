use std::marker::PhantomData;

use axum::{
    RequestPartsExt,
    extract::{Extension, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use jwkrs::JwkAuth;

pub type Rejection = (StatusCode, String);

#[derive(Clone, Debug)]
pub struct Authentication<T> {
    pub sub: String,
    _a: PhantomData<T>,
}

#[derive(Clone, Debug)]
pub struct Header {}

impl<S> FromRequestParts<S> for Authentication<Header>
where
    S: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the JwkAuth from the Extension
        let jwk = parts.extract::<Extension<JwkAuth>>().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing extension.".to_string(),
            )
        })?;

        // Extract the JWT token from the Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Missing or invalid Authorization header.".to_string(),
                )
            })?;
        let token = bearer.token();

        // Verify the token and extract claims
        let verified_claims = jwk.0.verify(token.trim()).await.ok_or({
            (
                StatusCode::UNAUTHORIZED,
                "Couldn't verify token.".to_string(),
            )
        })?;
        let sub = verified_claims.claims.sub;

        // Return the Authentication object
        Ok(Authentication {
            sub,
            _a: PhantomData,
        })
    }
}
