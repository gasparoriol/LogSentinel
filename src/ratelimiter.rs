use governor::{Quota, RateLimiter, state::keyed::DashMapStateStore, clock::DefaultClock};

use nonzero_ext::nonzero;
use std::time::Duration;

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

pub struct AlertRateLimiter {
    rate_limiter: KeyedLimiter,
}

impl AlertRateLimiter {
    pub fn new() -> Self {
        let quota = Quota::with_period(Duration::from_secs(30))
          .unwrap()
        .allow_burst(nonzero!(3u32));
        
        Self {
            rate_limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check_alert(&self, key: &str) -> bool {
        self.rate_limiter.check_key(&key.to_string()).is_ok()
    }

}
        