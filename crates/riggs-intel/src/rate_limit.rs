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

    pub async fn acquire(&self) {
        loop {
            self.try_refill().await;

            let current = self.tokens.load(Ordering::Acquire);
            if current > 0 {
                if self
                    .tokens
                    .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
                continue;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
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
