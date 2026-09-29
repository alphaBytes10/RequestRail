//! Distributed (Redis-backed) security guards.
//!
//! These guards use a Redis connection pool to maintain state across
//! multiple instances of the RequestRail gateway, enabling true
//! distributed rate limiting and replay protection.

use r2d2::Pool;
use redis::Client;
use redis::Commands;
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;
use std::time::Duration;

/// Distributed token-bucket rate limiting using Redis.
pub struct RedisRateLimitGuard {
    pool: Pool<Client>,
    capacity: u32,
    refill_rate: f64,
}

impl RedisRateLimitGuard {
    /// Create a new distributed rate limit guard.
    pub fn new(redis_url: &str, capacity: u32, requests_per_second: f64) -> Result<Self, GuardError> {
        let client = Client::open(redis_url)
            .map_err(|e| GuardError::Configuration(format!("Invalid Redis URL: {e}")))?;
        
        let pool = Pool::builder()
            .build(client)
            .map_err(|e| GuardError::Configuration(format!("Failed to create Redis pool: {e}")))?;

        Ok(Self {
            pool,
            capacity,
            refill_rate: requests_per_second,
        })
    }

    fn client_key(ctx: &Context) -> String {
        let id = ctx.source.clone()
            .or_else(|| ctx.remote_addr.clone())
            .unwrap_or_else(|| "anonymous".to_string());
        format!("requestrail:ratelimit:{id}")
    }
}

impl Guard for RedisRateLimitGuard {
    fn name(&self) -> &str {
        "redis_rate_limiter"
    }

    fn description(&self) -> &str {
        "Distributed token-bucket rate limiter per client identity"
    }

    fn priority(&self) -> u32 {
        10
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let mut conn = self.pool.get()
            .map_err(|e| GuardError::Internal(format!("Redis pool error: {e}")))?;

        let key = Self::client_key(ctx);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Basic distributed token bucket using a Lua script
        let script = redis::Script::new(r#"
            let tokens_key = KEYS[1]
            let timestamp_key = KEYS[2]
            let capacity = tonumber(ARGV[1])
            let refill_rate = tonumber(ARGV[2])
            let now = tonumber(ARGV[3])
            
            local tokens = tonumber(redis.call("GET", tokens_key))
            if tokens == nil then
                tokens = capacity
            end
            
            local last_refill = tonumber(redis.call("GET", timestamp_key))
            if last_refill == nil then
                last_refill = now
            end
            
            local delta = now - last_refill
            tokens = math.min(capacity, tokens + (delta * refill_rate))
            
            if tokens >= 1.0 then
                tokens = tokens - 1.0
                redis.call("SET", tokens_key, tokens)
                redis.call("SET", timestamp_key, now)
                -- Expire keys to prevent memory leaks
                redis.call("EXPIRE", tokens_key, 86400)
                redis.call("EXPIRE", timestamp_key, 86400)
                return 1
            else
                return 0
            end
        "#);

        let allowed: bool = script
            .key(format!("{key}:tokens"))
            .key(format!("{key}:ts"))
            .arg(self.capacity)
            .arg(self.refill_rate)
            .arg(now)
            .invoke(&mut *conn)
            .map_err(|e| GuardError::Internal(format!("Redis script error: {e}")))?;

        if allowed {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block(format!(
                "rate limit exceeded for client '{}'", key
            )))
        }
    }
}

/// Distributed nonce-based replay protection using Redis.
pub struct RedisReplayProtectionGuard {
    pool: Pool<Client>,
    window: Duration,
}

impl RedisReplayProtectionGuard {
    /// Create a new distributed replay protection guard.
    pub fn new(redis_url: &str, window: Duration) -> Result<Self, GuardError> {
        let client = Client::open(redis_url)
            .map_err(|e| GuardError::Configuration(format!("Invalid Redis URL: {e}")))?;
        
        let pool = Pool::builder()
            .build(client)
            .map_err(|e| GuardError::Configuration(format!("Failed to create Redis pool: {e}")))?;

        Ok(Self { pool, window })
    }
}

impl Guard for RedisReplayProtectionGuard {
    fn name(&self) -> &str {
        "redis_replay_protection"
    }

    fn description(&self) -> &str {
        "Distributed nonce-based replay attack prevention"
    }

    fn priority(&self) -> u32 {
        4
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let nonce = ctx.nonce.as_deref().ok_or_else(|| {
            GuardError::MissingField("nonce".into())
        })?;

        let mut conn = self.pool.get()
            .map_err(|e| GuardError::Internal(format!("Redis pool error: {e}")))?;

        let key = format!("requestrail:nonce:{nonce}");
        
        // SETNX (Set if Not eXists)
        let set: bool = conn.set_nx(&key, 1)
            .map_err(|e| GuardError::Internal(format!("Redis SETNX error: {e}")))?;

        if set {
            // Set expiration
            let _: () = conn.expire(&key, self.window.as_secs() as i64)
                .map_err(|e| GuardError::Internal(format!("Redis EXPIRE error: {e}")))?;
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block(format!(
                "replay detected: nonce '{nonce}' already used across distributed cluster"
            )))
        }
    }
}
