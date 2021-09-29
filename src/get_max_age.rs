use std::time::Duration;

use reqwest::header;

/// Method to get max-age from reqwest::Response
pub fn get_max_age(response: &reqwest::Response) -> Option<Duration> {
    let headers = response.headers();
    let cache_control = headers.get(header::CACHE_CONTROL)?;
    let cache_control = cache_control.to_str().ok()?;

    let max_age = cache_control
        .split(',')
        .filter_map(|kv| {
            let mut split = kv.split('=');
            Some((split.next()?, split.next()?))
        })
        .filter(|(k, _)| k.trim() == "max-age")
        .map(|(_, v)| v)
        .next()?;

    let max_age = max_age.parse::<u64>().ok()?;

    Some(Duration::from_secs(max_age))
}
