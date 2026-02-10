use governor::{Quota, RateLimiter, state::InMemoryState, state::keyed::GovRateLimiter, state::keyed::DashMapStateStore};
use std::num::NonZeroU32;
use nonzero_ext::nonzero;
use std::time::Duration;

type KeyedLimiter = GovRateLimiter<String, DashMapStateStore<String>, InMemoryState>;

pub struct AlertRateLimiter {
    rate_limiter: KeyedLimiter,
}

impl AlertRateLimiter {
    pub fn new() -> Self {
        let quota = Quota::with_period(Duration::from_secs(30))
          .unwrap()
        .allow_burst(nonzero!(3u32));
        
        Self {
            rate_limiter: GovRateLimiter::keyed(quota),
        }
    }

    pub fn check_alert(&self, key: &str) -> bool {
        self.rate_limiter.check_key(&key.to_string()).is_ok()
    }

}
        