use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::bloom::BloomFilter;
use crate::clients::malwarebazaar::MalwareBazaarClient;
use crate::clients::urlhaus::UrlhausClient;
use riggs_types::config::FeedsConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEntry {
    pub ioc_type: String,
    pub value: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub description: String,
    pub affected_package: String,
    pub affected_versions: String,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
}

pub enum FeedUpdate {
    BloomFilterReady(BloomFilter),
    IocBatch(Vec<IocEntry>),
    CveBatch(Vec<CveEntry>),
}

pub struct FeedManager {
    config: FeedsConfig,
    tx: mpsc::Sender<FeedUpdate>,
    malwarebazaar: MalwareBazaarClient,
    urlhaus: UrlhausClient,
}

impl FeedManager {
    pub fn new(config: FeedsConfig, tx: mpsc::Sender<FeedUpdate>) -> Self {
        Self {
            config,
            tx,
            malwarebazaar: MalwareBazaarClient::new(),
            urlhaus: UrlhausClient::new(),
        }
    }

    pub async fn run(&self) {
        let mb_interval = tokio::time::Duration::from_secs(
            self.config.malwarebazaar_interval_hours as u64 * 3600,
        );
        let uh_interval = tokio::time::Duration::from_secs(
            self.config.urlhaus_interval_hours as u64 * 3600,
        );

        let mut mb_ticker = tokio::time::interval(mb_interval);
        let mut uh_ticker = tokio::time::interval(uh_interval);

        // First tick fires immediately
        loop {
            tokio::select! {
                _ = mb_ticker.tick(), if self.config.malwarebazaar_enabled => {
                    self.refresh_malwarebazaar().await;
                }
                _ = uh_ticker.tick(), if self.config.urlhaus_enabled => {
                    self.refresh_urlhaus().await;
                }
            }
        }
    }

    async fn refresh_malwarebazaar(&self) {
        tracing::info!("refreshing MalwareBazaar hash feed");
        match self.malwarebazaar.download_recent_hashes().await {
            Ok(hashes) => {
                let mut bloom = BloomFilter::new(hashes.len().max(10_000), 0.001);
                for hash in &hashes {
                    bloom.insert(hash.as_bytes());
                }
                tracing::info!("built bloom filter with {} hashes", bloom.len());
                if self.tx.send(FeedUpdate::BloomFilterReady(bloom)).await.is_err() {
                    tracing::warn!("feed update receiver dropped");
                }
            }
            Err(e) => {
                tracing::error!("failed to refresh MalwareBazaar feed: {e}");
            }
        }
    }

    async fn refresh_urlhaus(&self) {
        tracing::info!("refreshing URLhaus feed");
        match self.urlhaus.download_recent().await {
            Ok(entries) => {
                let iocs: Vec<IocEntry> = entries
                    .into_iter()
                    .map(|e| IocEntry {
                        ioc_type: "url".to_string(),
                        value: e.url,
                        description: format!("URLhaus threat: {}", e.threat),
                        severity: match e.url_status.as_str() {
                            "online" => "high".to_string(),
                            _ => "medium".to_string(),
                        },
                    })
                    .collect();
                tracing::info!("converted {} URLhaus entries to IOCs", iocs.len());
                if self.tx.send(FeedUpdate::IocBatch(iocs)).await.is_err() {
                    tracing::warn!("feed update receiver dropped");
                }
            }
            Err(e) => {
                tracing::error!("failed to refresh URLhaus feed: {e}");
            }
        }
    }
}
