use governor::{Quota, RateLimiter, state::keyed::DashMapStateStore, clock::DefaultClock};
use std::time::Duration;
use std::num::NonZeroU32;
use crate::config::RateLimitConfig;
use crate::error::{AppError, Result};

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

pub struct AlertRateLimiter {
    rate_limiter: KeyedLimiter,
}

impl AlertRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Result<Self> {
        let period = Duration::from_secs(config.period_seconds);
        let quota = Quota::with_period(period)
            .ok_or_else(|| AppError::RateLimit(format!(
                "period_seconds ({}) must be greater than zero", config.period_seconds
            )))?;

        let burst = NonZeroU32::new(config.burst)
            .ok_or_else(|| AppError::RateLimit(format!(
                "burst ({}) must be greater than zero", config.burst
            )))?;

        Ok(Self {
            rate_limiter: RateLimiter::keyed(quota.allow_burst(burst)),
        })
    }

    pub fn check_alert(&self, key: &str) -> bool {
        self.rate_limiter.check_key(&key.to_string()).is_ok()
    }
}