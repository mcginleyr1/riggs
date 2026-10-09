use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct RateLimiter {
    max_tokens: u32,
    tokens: AtomicU32,
    refill_interval: Duration,
    last_refill: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            max_tokens: max_per_minute,
            tokens: AtomicU32::new(max_per_minute),
            refill_interval: Duration::from_secs(60),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Take a token if one is left. Lookups run on the detection path, which
    /// must not wait for API quota, so this never sleeps.
    pub async fn try_acquire(&self) -> bool {
        self.try_refill().await;
        self.tokens
            .try_update(Ordering::AcqRel, Ordering::Acquire, |t| t.checked_sub(1))
            .is_ok()
    }

    async fn try_refill(&self) {
        let mut last = self.last_refill.lock().await;
        let elapsed = last.elapsed();
        if elapsed >= self.refill_interval {
            let periods = (elapsed.as_millis() / self.refill_interval.as_millis()) as u32;
            let refill_amount = periods.saturating_mul(self.max_tokens);
            let current = self.tokens.load(Ordering::Acquire);
            let new_val = current.saturating_add(refill_amount).min(self.max_tokens);
            self.tokens.store(new_val, Ordering::Release);
            *last = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exhausted_quota_is_refused_without_waiting() {
        let limiter = RateLimiter::new(1);

        assert!(limiter.try_acquire().await);
        assert!(!limiter.try_acquire().await);
    }
}
