use std::marker::PhantomData;

use axum::{
    async_trait,
    extract::{Extension, FromRequest, Query, RequestParts},
    http::{header::AUTHORIZATION, StatusCode},
};
use jwkrs::JwkAuth;
use serde::Deserialize;

pub type Rejection = (StatusCode, String);

#[derive(Clone, Debug)]
pub struct Authentication<T> {
    pub sub: String,
    _a: PhantomData<T>,
}

#[derive(Clone, Debug)]
pub struct Header {}

#[async_trait]
impl<B> FromRequest<B> for Authentication<Header>
where
    B: Send,
{
    type Rejection = Rejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Rejection> {
        let token = extract_jwt_from_header(req)?;

        let auth = verify_token(req, token).await?;

        Ok(auth)
    }
}

async fn verify_token<T, B>(
    req: &mut RequestParts<B>,
    token: String,
) -> Result<Authentication<T>, Rejection>
where
    B: Send,
{
    let Extension(jwk) = Extension::<JwkAuth>::from_request(req).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    })?;
    let verified_claims = jwk.verify(&token).await.ok_or({
        (
            StatusCode::UNAUTHORIZED,
            "Couldn't verify token.".to_string(),
        )
    })?;
    let sub = verified_claims.claims.sub;
    let auth = Authentication {
        sub,
        _a: PhantomData,
    };
    Ok(auth)
}
#[derive(Clone, Debug)]
pub struct QueryString {}

#[async_trait]
impl<B> FromRequest<B> for Authentication<QueryString>
where
    B: Send,
{
    type Rejection = Rejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Rejection> {
        let token = extract_jwt_from_querystring(req).await?;
        let auth = verify_token(req, token).await?;

        Ok(auth)
    }
}

#[derive(Debug, PartialEq, Deserialize)]
struct AuthQuery {
    token: String,
}

fn extract_jwt_from_header<B>(req: &mut RequestParts<B>) -> Result<String, (StatusCode, String)> {
    let header = req
        .headers()
        .and_then(|headers| headers.get(AUTHORIZATION))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Authorization header not found.".to_string(),
        ))?;

    let auth_header = std::str::from_utf8(header.as_bytes()).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Encoding Error while reading authorization header.".to_string(),
        )
    })?;

    const BEARER: &str = "Bearer ";

    Ok(auth_header.trim_start_matches(BEARER).to_owned())
}
async fn extract_jwt_from_querystring<B>(
    req: &mut RequestParts<B>,
) -> Result<String, (StatusCode, String)>
where
    B: Send,
{
    let token = &Query::<AuthQuery>::from_request(req)
        .await
        .map_err(|_e| {
            (
                StatusCode::UNAUTHORIZED,
                "Couldn't get token from query string.".to_string(),
            )
        })?
        .token;

    Ok(token.clone())
}
