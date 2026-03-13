use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::info;

use riggs_types::events::{EventId, ProcessContext, RiggsEvent, StorylineId};
use riggs_types::verdict::Verdict;

const THREAT_SCORE_THRESHOLD: f32 = 0.5;

pub struct Storyline {
    pub id: StorylineId,
    pub root_process: ProcessContext,
    pub events: Vec<EventId>,
    pub verdicts: Vec<Verdict>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub threat_score: f32,
    pub process_tree: Vec<ProcessContext>,
}

impl fmt::Display for Storyline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Storyline({}, root={} pid={}, events={}, threat={:.2}, age={}s)",
            self.id,
            self.root_process.name,
            self.root_process.pid,
            self.events.len(),
            self.threat_score,
            (Utc::now() - self.created_at).num_seconds(),
        )
    }
}

pub struct StorylineCorrelator {
    storylines: HashMap<StorylineId, Storyline>,
    pid_to_storyline: HashMap<u32, StorylineId>,
}

impl StorylineCorrelator {
    pub fn new() -> Self {
        Self {
            storylines: HashMap::new(),
            pid_to_storyline: HashMap::new(),
        }
    }

    /// Assign an event to an existing storyline or create a new one.
    ///
    /// Process tree tracking: if the event's process has a parent whose PID is
    /// already associated with a storyline, the event joins that storyline.
    /// Otherwise a new storyline is created rooted at the current process.
    pub fn correlate(&mut self, event: &RiggsEvent) -> StorylineId {
        let ctx = extract_process_context(event);
        let event_id = extract_event_id(event);
        let now = Utc::now();

        // Check if this process already belongs to a storyline
        if let Some(existing_id) = self.pid_to_storyline.get(&ctx.pid) {
            let existing_id = existing_id.clone();
            if let Some(storyline) = self.storylines.get_mut(&existing_id) {
                storyline.events.push(event_id);
                storyline.updated_at = now;
                return existing_id;
            }
        }

        // Check if the parent process belongs to an existing storyline
        if let Some(parent_id) = self.pid_to_storyline.get(&ctx.ppid) {
            let parent_id = parent_id.clone();
            if let Some(storyline) = self.storylines.get_mut(&parent_id) {
                storyline.events.push(event_id);
                storyline.updated_at = now;
                let already_tracked = storyline.process_tree.iter().any(|p| p.pid == ctx.pid);
                if !already_tracked {
                    storyline.process_tree.push(ctx.clone());
                }
                self.pid_to_storyline.insert(ctx.pid, parent_id.clone());
                info!(
                    pid = ctx.pid,
                    ppid = ctx.ppid,
                    storyline = ?parent_id,
                    "process joined parent storyline"
                );
                return parent_id;
            }
        }

        // No existing storyline found -- create a new one
        let storyline_id = StorylineId::new();
        let storyline = Storyline {
            id: storyline_id.clone(),
            root_process: ctx.clone(),
            events: vec![event_id],
            verdicts: Vec::new(),
            created_at: now,
            updated_at: now,
            threat_score: 0.0,
            process_tree: vec![ctx.clone()],
        };

        self.pid_to_storyline.insert(ctx.pid, storyline_id.clone());
        self.storylines.insert(storyline_id.clone(), storyline);
        info!(
            pid = ctx.pid,
            storyline = ?storyline_id,
            "created new storyline"
        );

        storyline_id
    }

    pub fn add_verdict(&mut self, storyline_id: &StorylineId, verdict: Verdict) {
        if let Some(storyline) = self.storylines.get_mut(storyline_id) {
            storyline.verdicts.push(verdict);
            storyline.threat_score = recalculate_threat_score(&storyline.verdicts);
            storyline.updated_at = Utc::now();
        }
    }

    pub fn get_storyline(&self, id: &StorylineId) -> Option<&Storyline> {
        self.storylines.get(id)
    }

    pub fn active_storylines(&self) -> Vec<&Storyline> {
        let cutoff = Utc::now() - chrono::Duration::minutes(5);
        self.storylines
            .values()
            .filter(|s| s.updated_at > cutoff)
            .collect()
    }

    pub fn threat_storylines(&self) -> Vec<&Storyline> {
        self.storylines
            .values()
            .filter(|s| s.threat_score > THREAT_SCORE_THRESHOLD)
            .collect()
    }

    pub fn prune_inactive(&mut self, max_age: Duration) {
        let cutoff = Utc::now() - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::MAX);
        let stale_ids: Vec<StorylineId> = self
            .storylines
            .iter()
            .filter(|(_, s)| s.updated_at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &stale_ids {
            if let Some(storyline) = self.storylines.remove(id) {
                for ctx in &storyline.process_tree {
                    self.pid_to_storyline.remove(&ctx.pid);
                }
                info!(storyline = ?id, "pruned inactive storyline");
            }
        }
    }

    pub fn get_storyline_tree(&self, id: &StorylineId) -> Vec<ProcessContext> {
        self.storylines
            .get(id)
            .map(|s| s.process_tree.clone())
            .unwrap_or_default()
    }

    pub fn merge_storylines(&mut self, a: &StorylineId, b: &StorylineId) {
        let donor = match self.storylines.remove(b) {
            Some(s) => s,
            None => return,
        };

        let target = match self.storylines.get_mut(a) {
            Some(s) => s,
            None => {
                // Put donor back if target doesn't exist
                self.storylines.insert(donor.id.clone(), donor);
                return;
            }
        };

        target.events.extend(donor.events);
        target.verdicts.extend(donor.verdicts);
        target.threat_score = recalculate_threat_score(&target.verdicts);

        for ctx in &donor.process_tree {
            self.pid_to_storyline.insert(ctx.pid, a.clone());
            let already_tracked = target.process_tree.iter().any(|p| p.pid == ctx.pid);
            if !already_tracked {
                target.process_tree.push(ctx.clone());
            }
        }

        if donor.created_at < target.created_at {
            target.created_at = donor.created_at;
        }
        target.updated_at = Utc::now();

        info!(
            target = ?a,
            merged_from = ?b,
            "merged storylines"
        );
    }

    pub fn storyline_summary(&self, id: &StorylineId) -> Option<String> {
        let storyline = self.storylines.get(id)?;
        let process_names: Vec<&str> = storyline
            .process_tree
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        let age_secs = (Utc::now() - storyline.created_at).num_seconds();

        Some(format!(
            "Storyline {} | root: {} (pid {}) | {} events | {} verdicts | \
             threat: {:.2} | processes: [{}] | age: {}s",
            storyline.id,
            storyline.root_process.name,
            storyline.root_process.pid,
            storyline.events.len(),
            storyline.verdicts.len(),
            storyline.threat_score,
            process_names.join(", "),
            age_secs,
        ))
    }
}

impl Default for StorylineCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

fn recalculate_threat_score(verdicts: &[Verdict]) -> f32 {
    if verdicts.is_empty() {
        return 0.0;
    }

    // Weighted average of confidence scores, biased toward higher-confidence verdicts
    let total_confidence: f32 = verdicts.iter().map(|v| v.confidence).sum();
    let max_confidence: f32 = verdicts
        .iter()
        .map(|v| v.confidence)
        .fold(0.0_f32, f32::max);

    // Blend average and max: the more verdicts, the higher the score trends
    let avg = total_confidence / verdicts.len() as f32;
    let count_factor = (verdicts.len() as f32).ln_1p() / 3.0;

    (avg * 0.4 + max_confidence * 0.6 + count_factor * 0.1).clamp(0.0, 1.0)
}

fn extract_process_context(event: &RiggsEvent) -> &ProcessContext {
    match event {
        RiggsEvent::Process(e) => &e.process_context,
        RiggsEvent::File(e) => &e.process_context,
        RiggsEvent::Network(e) => &e.process_context,
        RiggsEvent::Dns(e) => &e.process_context,
        RiggsEvent::Auth(e) => &e.process_context,
        RiggsEvent::Kernel(e) => &e.process_context,
    }
}

fn extract_event_id(event: &RiggsEvent) -> EventId {
    match event {
        RiggsEvent::Process(e) => e.event_id.clone(),
        RiggsEvent::File(e) => e.event_id.clone(),
        RiggsEvent::Network(e) => e.event_id.clone(),
        RiggsEvent::Dns(e) => e.event_id.clone(),
        RiggsEvent::Auth(e) => e.event_id.clone(),
        RiggsEvent::Kernel(e) => e.event_id.clone(),
    }
}
