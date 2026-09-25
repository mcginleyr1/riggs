use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::info;

use riggs_types::events::{EventId, ProcessAction, ProcessContext, RiggsEvent, StorylineId};
use riggs_types::verdict::Verdict;

const DEFAULT_THREAT_SCORE_THRESHOLD: f32 = 0.5;
/// Default cap on event ids retained per storyline.
const DEFAULT_MAX_EVENTS_PER_STORYLINE: usize = 1024;
/// Default cadence for correlate()'s opportunistic idle-storyline pruning.
const DEFAULT_PRUNE_INTERVAL_SECS: i64 = 60;
/// Default idle age after which a storyline is pruned.
const DEFAULT_STORYLINE_MAX_AGE: Duration = Duration::from_secs(60 * 60);

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
    last_prune: DateTime<Utc>,
    max_events_per_storyline: usize,
    max_age: Duration,
    prune_interval_secs: i64,
    threat_score_threshold: f32,
}

impl StorylineCorrelator {
    pub fn new() -> Self {
        Self {
            storylines: HashMap::new(),
            pid_to_storyline: HashMap::new(),
            last_prune: Utc::now(),
            max_events_per_storyline: DEFAULT_MAX_EVENTS_PER_STORYLINE,
            max_age: DEFAULT_STORYLINE_MAX_AGE,
            prune_interval_secs: DEFAULT_PRUNE_INTERVAL_SECS,
            threat_score_threshold: DEFAULT_THREAT_SCORE_THRESHOLD,
        }
    }

    /// Override the score above which a storyline is treated as a threat.
    pub fn with_threat_threshold(mut self, threshold: f32) -> Self {
        self.threat_score_threshold = threshold;
        self
    }

    /// Override the per-storyline event cap, idle-prune age, and prune cadence.
    pub fn with_limits(
        mut self,
        max_events_per_storyline: usize,
        idle_secs: u64,
        prune_interval_secs: u64,
    ) -> Self {
        self.max_events_per_storyline = max_events_per_storyline.max(1);
        self.max_age = Duration::from_secs(idle_secs);
        self.prune_interval_secs = prune_interval_secs.max(1) as i64;
        self
    }

    /// Assign an event to an existing storyline or create a new one.
    ///
    /// Process tree tracking: if the event's process has a parent whose PID is
    /// already associated with a storyline, the event joins that storyline.
    /// Otherwise a new storyline is created rooted at the current process.
    pub fn correlate(&mut self, event: &RiggsEvent) -> StorylineId {
        let ctx = extract_process_context(event).clone();
        let event_id = extract_event_id(event);
        let now = Utc::now();

        // Opportunistically prune idle storylines so the maps stay bounded.
        if (now - self.last_prune).num_seconds() >= self.prune_interval_secs {
            self.prune_inactive(self.max_age);
            self.last_prune = now;
        }

        let storyline_id = self.assign(&ctx, event_id, now);

        // A process exit ends the pid's association, so a later reused pid does
        // not inherit this (possibly unrelated) process's storyline.
        if matches!(event, RiggsEvent::Process(pe) if pe.action == ProcessAction::Exit) {
            self.pid_to_storyline.remove(&ctx.pid);
        }

        storyline_id
    }

    fn assign(
        &mut self,
        ctx: &ProcessContext,
        event_id: EventId,
        now: DateTime<Utc>,
    ) -> StorylineId {
        // Check if this process already belongs to a storyline
        if let Some(existing_id) = self.pid_to_storyline.get(&ctx.pid) {
            let existing_id = existing_id.clone();
            if let Some(storyline) = self.storylines.get_mut(&existing_id) {
                push_capped(
                    &mut storyline.events,
                    event_id,
                    self.max_events_per_storyline,
                );
                storyline.updated_at = now;
                return existing_id;
            }
        }

        // Check if the parent process belongs to an existing storyline
        if let Some(parent_id) = self.pid_to_storyline.get(&ctx.ppid) {
            let parent_id = parent_id.clone();
            if let Some(storyline) = self.storylines.get_mut(&parent_id) {
                push_capped(
                    &mut storyline.events,
                    event_id,
                    self.max_events_per_storyline,
                );
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
            .filter(|s| s.threat_score > self.threat_score_threshold)
            .collect()
    }

    pub fn prune_inactive(&mut self, max_age: Duration) {
        let cutoff =
            Utc::now() - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::MAX);
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

fn push_capped(events: &mut Vec<EventId>, id: EventId, max: usize) {
    events.push(id);
    if events.len() > max {
        let overflow = events.len() - max;
        events.drain(0..overflow);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_event(pid: u32, ppid: u32, action: ProcessAction) -> RiggsEvent {
        let ctx = ProcessContext {
            pid,
            ppid,
            name: "p".into(),
            path: "/p".into(),
            cmdline: "p".into(),
            user: "root".into(),
            storyline_id: StorylineId::new(),
        };
        RiggsEvent::new_process(action, ctx, None)
    }

    #[test]
    fn same_pid_shares_storyline() {
        let mut c = StorylineCorrelator::new();
        let a = c.correlate(&proc_event(100, 1, ProcessAction::Exec));
        let b = c.correlate(&proc_event(100, 1, ProcessAction::Fork));
        assert_eq!(a, b);
    }

    #[test]
    fn exit_clears_pid_so_reuse_starts_new_storyline() {
        let mut c = StorylineCorrelator::new();
        let first = c.correlate(&proc_event(100, 1, ProcessAction::Exec));
        c.correlate(&proc_event(100, 1, ProcessAction::Exit));
        // pid 100 recycled by an unrelated process -> must not inherit the old storyline
        let second = c.correlate(&proc_event(100, 1, ProcessAction::Exec));
        assert_ne!(first, second);
    }

    #[test]
    fn prune_inactive_drops_stale_storylines_and_pids() {
        let mut c = StorylineCorrelator::new();
        c.correlate(&proc_event(200, 1, ProcessAction::Exec));
        assert_eq!(c.storylines.len(), 1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        // A zero max-age means the cutoff is "now", so all prior storylines prune.
        c.prune_inactive(Duration::from_secs(0));
        assert_eq!(c.storylines.len(), 0);
        assert!(c.pid_to_storyline.is_empty());
    }
}
