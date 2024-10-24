use std::time::Duration;

use cache_control::CacheControl;
use reqwest::header;

pub fn get_max_age(response: &reqwest::Response) -> Option<Duration> {
    let headers = response.headers();
    let cache_control_header = headers.get(header::CACHE_CONTROL)?;
    let cache_control_str = cache_control_header.to_str().ok()?;

    let cache_control = CacheControl::from_value(cache_control_str)?;

    if let Some(max_age) = cache_control.max_age {
        return Some(Duration::from_secs(max_age.as_secs()));
    }

    None
}
