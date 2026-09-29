//! Dynamic configuration for RequestRail.
//!
//! Loads declarative YAML configuration files to construct
//! complex security pipelines without recompiling code.

use requestrail_core::Pipeline;
use requestrail_guards::{
    RateLimitGuard, PiiDetectionGuard, AuditLoggingGuard, 
    RegexFilterGuard, PromptInjectionGuard
};
use requestrail_guards::pii::PiiMode;
use requestrail_guards::redis_guards::{RedisRateLimitGuard, RedisReplayProtectionGuard};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct PipelineConfig {
    pub name: String,
    pub guards: Vec<GuardConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum GuardConfig {
    AuditLogging { preview_body: bool },
    RateLimit { capacity: u32, requests_per_second: f64 },
    RedisRateLimit { redis_url: String, capacity: u32, requests_per_second: f64 },
    RedisReplayProtection { redis_url: String, window_seconds: u64 },
    PiiDetection { mode: String }, // "block" or "redact"
    PromptInjection,
    RegexFilter { label: String, deny_patterns: Vec<RegexPattern> },
}

#[derive(Debug, Deserialize)]
pub struct RegexPattern {
    pub name: String,
    pub pattern: String,
}

/// Load a pipeline from a YAML configuration file.
pub fn load_pipeline<P: AsRef<Path>>(path: P) -> Result<Pipeline, Box<dyn std::error::Error>> {
    let yaml = fs::read_to_string(path)?;
    let config: PipelineConfig = serde_yaml::from_str(&yaml)?;
    
    let mut pipeline = Pipeline::new();

    for guard_config in config.guards {
        match guard_config {
            GuardConfig::AuditLogging { preview_body } => {
                let mut guard = AuditLoggingGuard::new();
                if preview_body {
                    guard = guard.with_body_preview();
                }
                pipeline = pipeline.with(guard);
            }
            GuardConfig::RateLimit { capacity, requests_per_second } => {
                pipeline = pipeline.with(RateLimitGuard::new(capacity, requests_per_second));
            }
            GuardConfig::RedisRateLimit { redis_url, capacity, requests_per_second } => {
                let guard = RedisRateLimitGuard::new(&redis_url, capacity, requests_per_second)?;
                pipeline = pipeline.with(guard);
            }
            GuardConfig::RedisReplayProtection { redis_url, window_seconds } => {
                let guard = RedisReplayProtectionGuard::new(&redis_url, Duration::from_secs(window_seconds))?;
                pipeline = pipeline.with(guard);
            }
            GuardConfig::PiiDetection { mode } => {
                let pii_mode = if mode.to_lowercase() == "redact" {
                    PiiMode::Redact
                } else {
                    PiiMode::Block
                };
                pipeline = pipeline.with(PiiDetectionGuard::new(pii_mode)?);
            }
            GuardConfig::PromptInjection => {
                pipeline = pipeline.with(PromptInjectionGuard::new()?);
            }
            GuardConfig::RegexFilter { label, deny_patterns } => {
                let mut guard = RegexFilterGuard::new(&label);
                for p in deny_patterns {
                    guard = guard.deny(&p.name, &p.pattern)?;
                }
                pipeline = pipeline.with(guard);
            }
        }
    }

    Ok(pipeline)
}
