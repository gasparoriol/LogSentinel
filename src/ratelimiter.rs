use governor::{Quota, RateLimiter, state::keyed::DashMapStateStore, clock::DefaultClock};

use std::time::Duration;

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

pub struct AlertRateLimiter {
    rate_limiter: KeyedLimiter,
}

use crate::config::RateLimitConfig;

use std::num::NonZeroU32;

impl AlertRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let quota = Quota::with_period(Duration::from_secs(config.period_seconds))
          .expect("Invalid period")
          .allow_burst(NonZeroU32::new(config.burst).expect("Burst must be non-zero"));
        
        Self {
            rate_limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check_alert(&self, key: &str) -> bool {
        self.rate_limiter.check_key(&key.to_string()).is_ok()
    }

}
        