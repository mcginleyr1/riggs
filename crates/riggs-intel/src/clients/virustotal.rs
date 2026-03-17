use riggs_types::errors::RiggsError;
use serde::Deserialize;

use crate::rate_limit::RateLimiter;

#[derive(Debug, Clone, Deserialize)]
pub struct VtResult {
    pub malicious_count: u32,
    pub suspicious_count: u32,
    pub total_engines: u32,
}

pub struct VtClient {
    client: reqwest::Client,
    api_key: String,
    rate_limiter: RateLimiter,
}

#[derive(Deserialize)]
struct VtApiResponse {
    data: Option<VtData>,
}

#[derive(Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: VtAnalysisStats,
}

#[derive(Deserialize)]
struct VtAnalysisStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
    timeout: u32,
    #[serde(rename = "confirmed-timeout")]
    confirmed_timeout: Option<u32>,
    failure: Option<u32>,
    #[serde(rename = "type-unsupported")]
    type_unsupported: Option<u32>,
}

impl VtClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            rate_limiter: RateLimiter::new(4),
        }
    }

    pub async fn lookup_hash(&self, hash: &str) -> Result<Option<VtResult>, RiggsError> {
        self.rate_limiter.acquire().await;

        let url = format!("https://www.virustotal.com/api/v3/files/{hash}");

        let response = self
            .client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| RiggsError::Intel(format!("VT request failed: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(RiggsError::Intel(format!(
                "VT API returned status {}",
                response.status()
            )));
        }

        let body: VtApiResponse = response
            .json()
            .await
            .map_err(|e| RiggsError::Intel(format!("VT response parse error: {e}")))?;

        let data = match body.data {
            Some(d) => d,
            None => return Ok(None),
        };

        let stats = &data.attributes.last_analysis_stats;
        let total = stats.malicious
            + stats.suspicious
            + stats.undetected
            + stats.harmless
            + stats.timeout
            + stats.confirmed_timeout.unwrap_or(0)
            + stats.failure.unwrap_or(0)
            + stats.type_unsupported.unwrap_or(0);

        Ok(Some(VtResult {
            malicious_count: stats.malicious,
            suspicious_count: stats.suspicious,
            total_engines: total,
        }))
    }
}
