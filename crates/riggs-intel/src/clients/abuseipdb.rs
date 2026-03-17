use riggs_types::errors::RiggsError;
use serde::Deserialize;

use crate::rate_limit::RateLimiter;

#[derive(Debug, Clone, Deserialize)]
pub struct AbuseIpResult {
    pub abuse_confidence_score: u32,
    pub total_reports: u32,
    pub is_tor: bool,
}

pub struct AbuseIpdbClient {
    client: reqwest::Client,
    api_key: String,
    rate_limiter: RateLimiter,
}

#[derive(Deserialize)]
struct AbuseIpdbResponse {
    data: AbuseIpdbData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseIpdbData {
    abuse_confidence_score: u32,
    total_reports: u32,
    is_tor: bool,
}

impl AbuseIpdbClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            rate_limiter: RateLimiter::new(60),
        }
    }

    pub async fn check_ip(&self, ip: &str) -> Result<Option<AbuseIpResult>, RiggsError> {
        self.rate_limiter.acquire().await;

        let response = self
            .client
            .get("https://api.abuseipdb.com/api/v2/check")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .send()
            .await
            .map_err(|e| RiggsError::Intel(format!("AbuseIPDB request failed: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(RiggsError::Intel(format!(
                "AbuseIPDB API returned status {}",
                response.status()
            )));
        }

        let body: AbuseIpdbResponse = response
            .json()
            .await
            .map_err(|e| RiggsError::Intel(format!("AbuseIPDB response parse error: {e}")))?;

        Ok(Some(AbuseIpResult {
            abuse_confidence_score: body.data.abuse_confidence_score,
            total_reports: body.data.total_reports,
            is_tor: body.data.is_tor,
        }))
    }
}
