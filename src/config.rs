use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct JwkConfiguration {
    pub jwk_url: String,
    pub audience: String,
    pub issuers: HashSet<String>,
}
