use std::time::Duration;

use reqwest::header;

/// Method to get max-age from reqwest::Response
pub fn get_max_age(response: &reqwest::Response) -> Option<Duration> {
    let max_age = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| {
            header
                .split(',')
                .filter_map(|kv| {
                    let mut split = kv.split('=');
                    Some((split.next()?, split.next()?))
                })
                .filter(|(k, _)| k.trim() == "max-age")
                .next()
        })
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .map(Duration::from_secs);

    max_age
}
