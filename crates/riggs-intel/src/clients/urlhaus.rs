use riggs_types::errors::RiggsError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlhausEntry {
    pub url: String,
    pub url_status: String,
    pub threat: String,
}

pub struct UrlhausClient {
    client: reqwest::Client,
}

impl UrlhausClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn download_recent(&self) -> Result<Vec<UrlhausEntry>, RiggsError> {
        let url = "https://urlhaus.abuse.ch/downloads/csv_recent/";

        let response = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.client
                .get(url)
                .send()
                .await
                .map_err(|e| RiggsError::Intel(format!("URLhaus request failed: {e}")))
        })
        .await
        .map_err(|_| RiggsError::Intel("URLhaus download timed out after 30s".into()))??;

        if !response.status().is_success() {
            return Err(RiggsError::Intel(format!(
                "URLhaus returned status {}",
                response.status()
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| RiggsError::Intel(format!("URLhaus body read error: {e}")))?;

        let entries: Vec<UrlhausEntry> = text
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(parse_csv_line)
            .collect();

        tracing::info!("downloaded {} entries from URLhaus", entries.len());
        Ok(entries)
    }
}

impl Default for UrlhausClient {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_csv_line(line: &str) -> Option<UrlhausEntry> {
    // URLhaus CSV format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    // Fields are quoted with double quotes
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() < 6 {
        return None;
    }

    let unquote = |s: &str| s.trim_matches('"').to_string();

    Some(UrlhausEntry {
        url: unquote(fields[2]),
        url_status: unquote(fields[3]),
        threat: unquote(fields[5]),
    })
}
