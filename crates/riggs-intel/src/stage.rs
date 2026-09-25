use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::Utc;

use riggs_engine::DetectionStage;
use riggs_engine::StageVerdict;
use riggs_types::errors::RiggsError;
use riggs_types::events::{EventId, RiggsEvent};
use riggs_types::verdict::{DetectionSource, ThreatLevel, Verdict};

use crate::bloom::BloomFilter;
use crate::cache::{CachedVerdict, HashVerdictCache};
use crate::clients::abuseipdb::AbuseIpdbClient;
use crate::clients::virustotal::VtClient;

pub struct ThreatIntelStage {
    bloom: Arc<RwLock<BloomFilter>>,
    cache: Arc<HashVerdictCache>,
    vt_client: Option<VtClient>,
    abuseipdb_client: Option<AbuseIpdbClient>,
}

impl ThreatIntelStage {
    pub fn new(
        bloom: Arc<RwLock<BloomFilter>>,
        cache: Arc<HashVerdictCache>,
        vt_client: Option<VtClient>,
        abuseipdb_client: Option<AbuseIpdbClient>,
    ) -> Self {
        Self {
            bloom,
            cache,
            vt_client,
            abuseipdb_client,
        }
    }

    fn check_bloom(&self, item: &[u8]) -> bool {
        let bloom = self.bloom.read().unwrap_or_else(|e| e.into_inner());
        bloom.contains(item)
    }

    async fn analyze_file_hash(
        &self,
        event_id: EventId,
        hash: &str,
    ) -> Result<StageVerdict, RiggsError> {
        let bloom_hit = self.check_bloom(hash.as_bytes());

        if let Some(cached) = self.cache.get(hash) {
            // A cached Clean is only trustworthy while the hash is still absent
            // from the feed. Once a feed refresh adds it to the bloom, bypass the
            // stale Clean and re-evaluate; other cached verdicts still stand.
            if !(bloom_hit && cached.threat_level == ThreatLevel::Clean) {
                return Ok(cached_to_stage_verdict(event_id, &cached));
            }
        }

        if !bloom_hit {
            return Ok(StageVerdict::Clean);
        }

        let vt_client = match &self.vt_client {
            Some(c) => c,
            None => {
                return Ok(StageVerdict::Suspicious(Verdict::new(
                    event_id,
                    ThreatLevel::Suspicious,
                    0.3,
                    DetectionSource::ThreatIntel,
                    "hash matched known-malware bloom filter (no VT key to confirm)",
                )));
            }
        };

        match vt_client.lookup_hash(hash).await? {
            Some(vt) => {
                let (threat_level, confidence, desc) = if vt.malicious_count > 5 {
                    (
                        ThreatLevel::Malicious,
                        0.95,
                        format!(
                            "VirusTotal: {}/{} engines flagged malicious",
                            vt.malicious_count, vt.total_engines
                        ),
                    )
                } else if vt.malicious_count > 0 {
                    (
                        ThreatLevel::Suspicious,
                        0.5 + (vt.malicious_count as f32 / 10.0).min(0.4),
                        format!(
                            "VirusTotal: {}/{} engines flagged malicious",
                            vt.malicious_count, vt.total_engines
                        ),
                    )
                } else {
                    (
                        ThreatLevel::Clean,
                        0.9,
                        format!("VirusTotal: clean across {} engines", vt.total_engines),
                    )
                };

                let cached_verdict = CachedVerdict {
                    threat_level,
                    confidence,
                    source: DetectionSource::ThreatIntel,
                    cached_at: Utc::now(),
                    ttl_hours: self.cache.ttl_for_level(threat_level),
                };
                self.cache.put(hash, cached_verdict);

                let verdict = Verdict::new(
                    event_id,
                    threat_level,
                    confidence,
                    DetectionSource::ThreatIntel,
                    desc,
                );

                Ok(match threat_level {
                    ThreatLevel::Clean => StageVerdict::Clean,
                    ThreatLevel::Suspicious => StageVerdict::Suspicious(verdict),
                    ThreatLevel::Malicious => StageVerdict::Malicious(verdict),
                })
            }
            None => Ok(StageVerdict::Suspicious(Verdict::new(
                event_id,
                ThreatLevel::Suspicious,
                0.3,
                DetectionSource::ThreatIntel,
                "hash matched bloom filter but not found in VirusTotal",
            ))),
        }
    }

    async fn analyze_network(
        &self,
        event_id: EventId,
        dst_addr: &str,
    ) -> Result<StageVerdict, RiggsError> {
        let client = match &self.abuseipdb_client {
            Some(c) => c,
            None => return Ok(StageVerdict::Clean),
        };

        match client.check_ip(dst_addr).await? {
            Some(result) => {
                if result.abuse_confidence_score >= 80 {
                    let threat_level = if result.abuse_confidence_score >= 95 {
                        ThreatLevel::Malicious
                    } else {
                        ThreatLevel::Suspicious
                    };
                    let confidence = result.abuse_confidence_score as f32 / 100.0;
                    let desc = format!(
                        "AbuseIPDB: confidence={}, reports={}, tor={}",
                        result.abuse_confidence_score, result.total_reports, result.is_tor
                    );
                    let verdict = Verdict::new(
                        event_id,
                        threat_level,
                        confidence,
                        DetectionSource::ThreatIntel,
                        desc,
                    );
                    Ok(match threat_level {
                        ThreatLevel::Malicious => StageVerdict::Malicious(verdict),
                        _ => StageVerdict::Suspicious(verdict),
                    })
                } else {
                    Ok(StageVerdict::Clean)
                }
            }
            None => Ok(StageVerdict::Clean),
        }
    }

    fn analyze_dns(&self, event_id: EventId, domain: &str) -> StageVerdict {
        if self.check_bloom(domain.as_bytes()) {
            StageVerdict::Suspicious(Verdict::new(
                event_id,
                ThreatLevel::Suspicious,
                0.4,
                DetectionSource::ThreatIntel,
                format!("DNS query domain '{domain}' matched threat intel bloom filter"),
            ))
        } else {
            StageVerdict::Clean
        }
    }
}

fn event_id(event: &RiggsEvent) -> EventId {
    match event {
        RiggsEvent::Process(e) => e.event_id.clone(),
        RiggsEvent::File(e) => e.event_id.clone(),
        RiggsEvent::Network(e) => e.event_id.clone(),
        RiggsEvent::Dns(e) => e.event_id.clone(),
        RiggsEvent::Auth(e) => e.event_id.clone(),
        RiggsEvent::Kernel(e) => e.event_id.clone(),
    }
}

fn cached_to_stage_verdict(event_id: EventId, cached: &CachedVerdict) -> StageVerdict {
    let verdict = Verdict::new(
        event_id,
        cached.threat_level,
        cached.confidence,
        cached.source,
        "cached threat intel verdict",
    );
    match cached.threat_level {
        ThreatLevel::Clean => StageVerdict::Clean,
        ThreatLevel::Suspicious => StageVerdict::Suspicious(verdict),
        ThreatLevel::Malicious => StageVerdict::Malicious(verdict),
    }
}

#[async_trait]
impl DetectionStage for ThreatIntelStage {
    fn name(&self) -> &str {
        "threat-intel"
    }

    async fn analyze(&self, event: &RiggsEvent) -> Result<StageVerdict, RiggsError> {
        let eid = event_id(event);

        match event {
            RiggsEvent::File(file_event) => {
                let hash = match &file_event.hash {
                    Some(h) => h,
                    None => return Ok(StageVerdict::Clean),
                };
                self.analyze_file_hash(eid, hash).await
            }
            RiggsEvent::Network(net_event) => self.analyze_network(eid, &net_event.dst_addr).await,
            RiggsEvent::Dns(dns_event) => Ok(self.analyze_dns(eid, &dns_event.query)),
            _ => Ok(StageVerdict::Clean),
        }
    }
}
