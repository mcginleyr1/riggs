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

    /// The abuse.ch Auth-Key is part of the URL, so errors must never carry it
    /// (reqwest's Display includes the URL unless stripped).
    pub async fn download_recent(&self, auth_key: &str) -> Result<Vec<UrlhausEntry>, RiggsError> {
        let url = format!("https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv");

        let response = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.client.get(&url).send().await.map_err(|e| {
                RiggsError::Intel(format!("URLhaus request failed: {}", e.without_url()))
            })
        })
        .await
        .map_err(|_| RiggsError::Intel("URLhaus download timed out after 30s".into()))??;

        match response.status() {
            reqwest::StatusCode::UNAUTHORIZED => {
                return Err(RiggsError::Intel(
                    "URLhaus rejected [intel.feeds] abusech_auth_key (401)".into(),
                ))
            }
            status if !status.is_success() => {
                return Err(RiggsError::Intel(format!(
                    "URLhaus returned status {status}"
                )))
            }
            _ => {}
        }

        let text = response.text().await.map_err(|e| {
            RiggsError::Intel(format!("URLhaus body read error: {}", e.without_url()))
        })?;

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
    // Every field is double-quoted; URLs and tags may contain commas, so split
    // on the quoted separator rather than on bare commas.
    let fields: Vec<&str> = line.trim().trim_matches('"').split("\",\"").collect();
    if fields.len() < 6 {
        return None;
    }

    Some(UrlhausEntry {
        url: fields[2].to_string(),
        url_status: fields[3].to_string(),
        threat: fields[5].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commas_inside_quoted_fields_keep_columns_aligned() {
        let line = r#""3412345","2026-10-31 12:00:07","http://203.0.113.7:8099/a,b.sh","online","2026-10-31 12:00:07","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/3412345/","anon""#;
        let e = parse_csv_line(line).unwrap();
        assert_eq!(e.url, "http://203.0.113.7:8099/a,b.sh");
        assert_eq!(e.url_status, "online");
        assert_eq!(e.threat, "malware_download");

        // Empty quoted fields (offline entries have no last_online) keep their slot.
        let line = r#""3412346","2026-10-31 12:00:08","http://203.0.113.8/x","offline","","malware_download","","https://urlhaus.abuse.ch/url/3412346/","anon""#;
        let e = parse_csv_line(line).unwrap();
        assert_eq!(
            (e.url_status.as_str(), e.threat.as_str()),
            ("offline", "malware_download")
        );
    }
}
