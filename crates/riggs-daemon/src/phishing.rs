//! The phishing adapter: per-user engine state in memory, answers computed synchronously,
//! persistence handed to one writer task.
//!
//! `handle` runs on the async runtime for any local user, so it never waits on the store's
//! writer: it queues writes with `try_send` and drops them when the queue is full. A verdict is
//! advice shown to a person; nothing here reaches the detection pipeline, the response engine
//! or the threat counters.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use riggs_comms::PhishingQuery;
use riggs_phishing::engine::{message_fingerprint, Assessment, Change, LoginRow, SenderRow, User};
use riggs_phishing::policy::Policy;
use riggs_store::{PhishingWrite, RiggsStore, SenderEntry};
use riggs_types::errors::RiggsError;
use riggs_types::phishing::{
    CueCount, Level, LoginEntry, Mode, ObservationKind, PhishingRequest, PhishingResponse,
    PhishingStats, PhishingStatus, PhishingVerdict, VerdictEntry,
};
use sha2::{Digest, Sha256};
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

/// Writes waiting for the writer task; past this a write is dropped, never awaited.
pub const QUEUE_CAPACITY: usize = 1024;
/// Writes committed in one transaction.
const BATCH_MAX: usize = 256;
/// Verdict-log rows per uid per UTC day; later checks are answered and not logged.
const DAILY_LOG_CAP: u32 = 500;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

pub struct PhishingAdapter {
    /// The map lock is held only to find a user; the engine runs under that user's own lock,
    /// so one user's checks never wait on another's.
    users: Mutex<HashMap<u32, Arc<Mutex<User>>>>,
    /// Per uid: a UTC day and the verdict-log rows queued on it.
    logged: Mutex<HashMap<u32, (u64, u32)>>,
    policy: Arc<watch::Sender<Arc<Policy>>>,
    policy_path: PathBuf,
    /// Only read here; every write goes through `writes`.
    store: Arc<RiggsStore>,
    writes: mpsc::Sender<PhishingWrite>,
    dropped: AtomicU64,
}

impl PhishingAdapter {
    /// Builds every user from the stored rows. The returned queue is for [`write_batches`].
    pub fn new(
        store: Arc<RiggsStore>,
        policy: Arc<watch::Sender<Arc<Policy>>>,
        policy_path: PathBuf,
        capacity: usize,
    ) -> Result<(Self, mpsc::Receiver<PhishingWrite>), RiggsError> {
        let rows = store.phishing_load()?;
        let mut stored: HashMap<u32, (Vec<LoginRow>, Vec<SenderRow>)> = HashMap::new();
        for (uid, e) in rows.logins {
            stored.entry(uid).or_default().0.push(LoginRow {
                domain: e.domain,
                first_ms: e.first_ms,
                last_ms: e.last_ms,
                count: e.count,
            });
        }
        for (uid, e) in rows.senders {
            stored.entry(uid).or_default().1.push(SenderRow {
                key: e.key,
                first_ms: e.first_ms,
                first_msg: e.first_msg,
            });
        }

        let mut users = HashMap::new();
        let mut stale = 0;
        for (uid, (logins, senders)) in stored {
            // A login the public-suffix data no longer accepts must not cost the user the rest.
            let (valid, invalid): (Vec<_>, Vec<_>) = logins
                .into_iter()
                .partition(|row| User::new([row.clone()], []).is_ok());
            stale += invalid.len();
            let user = User::new(valid, senders).map_err(|_| {
                RiggsError::Store(format!("stored phishing state of uid {uid} does not load"))
            })?;
            users.insert(uid, Arc::new(Mutex::new(user)));
        }
        if stale > 0 {
            warn!(
                stale,
                "stored phishing logins that are no longer registrable domains were skipped"
            );
        }

        let (writes, queue) = mpsc::channel(capacity);
        let adapter = Self {
            users: Mutex::new(users),
            logged: Mutex::default(),
            policy,
            policy_path,
            store,
            writes,
            dropped: AtomicU64::new(0),
        };
        Ok((adapter, queue))
    }

    /// The uid's state, created empty on first use.
    fn user(&self, uid: u32) -> Result<Arc<Mutex<User>>, String> {
        Ok(Arc::clone(lock(&self.users)?.entry(uid).or_default()))
    }

    fn answer(
        &self,
        uid: u32,
        request: PhishingRequest,
        now_ms: u64,
    ) -> Result<PhishingResponse, String> {
        let policy = self.policy.borrow().clone();
        let mode = policy.mode();
        let quiet = || {
            PhishingResponse::Verdict(PhishingVerdict {
                level: Level::None,
                reasons: Vec::new(),
                show: false,
            })
        };
        match request {
            PhishingRequest::CheckMail(mail) => {
                mail.check_limits()?;
                if mode == Mode::Off {
                    return Ok(quiet());
                }
                let user = self.user(uid)?;
                let (assessment, change) = lock(&user)?.check_mail(&policy, &mail, now_ms);
                if let Some(change) = change {
                    self.queue(write(uid, change));
                }
                let msg = message_fingerprint(mail.provider, &mail.message_id);
                self.verdict(uid, mode, ObservationKind::Mail, msg, assessment, now_ms)
            }
            PhishingRequest::CheckPage(page) => {
                page.check_limits()?;
                if mode == Mode::Off {
                    return Ok(quiet());
                }
                let user = self.user(uid)?;
                let assessment = lock(&user)?.check_page(&policy, &page, now_ms);
                let msg = page_fingerprint(&assessment.domain, now_ms / DAY_MS);
                self.verdict(uid, mode, ObservationKind::Page, msg, assessment, now_ms)
            }
            PhishingRequest::LoginSeen(login) => {
                login.check_limits()?;
                if mode != Mode::Off {
                    let user = self.user(uid)?;
                    let mut user = lock(&user)?;
                    match user.login_seen(&policy, &login.host, now_ms, false) {
                        Ok(change) => self.queue(write(uid, change)),
                        // The reason can name one of the user's logins; the caller may be a
                        // page-controlled context, so it learns nothing either way.
                        Err(reason) => debug!(uid, %reason, "login not recorded"),
                    }
                }
                Ok(PhishingResponse::Ok)
            }
            PhishingRequest::Status => {
                let user = self.user(uid)?;
                let logins = lock(&user)?.logins().count() as u32;
                Ok(PhishingResponse::Status(PhishingStatus { mode, logins }))
            }
            PhishingRequest::SetMode { mode } => self.set_mode(mode),
            PhishingRequest::Trust { uid, domain } => {
                let user = self.user(uid)?;
                let mut user = lock(&user)?;
                let change = user
                    .login_seen(&policy, &domain, now_ms, true)
                    .map_err(|reason| format!("cannot trust {domain}: {reason}"))?;
                self.queue(write(uid, change));
                Ok(PhishingResponse::Ok)
            }
            PhishingRequest::Forget { uid, domain } => {
                let user = self.user(uid)?;
                let mut user = lock(&user)?;
                let change = user
                    .forget(&domain)
                    .ok_or_else(|| format!("{domain} is not a login of uid {uid}"))?;
                self.queue(write(uid, change));
                Ok(PhishingResponse::Ok)
            }
            PhishingRequest::Logins { uid } => {
                let user = self.user(uid)?;
                let logins = lock(&user)?.logins().map(login_entry).collect();
                Ok(PhishingResponse::Logins(logins))
            }
            PhishingRequest::Recent { uid, limit } => Ok(PhishingResponse::Recent(
                self.verdicts(uid)?
                    .into_iter()
                    .take(limit as usize)
                    .collect(),
            )),
            PhishingRequest::Stats { uid } => {
                let mut stats = PhishingStats {
                    total: 0,
                    caution: 0,
                    danger: 0,
                    cues: Vec::new(),
                };
                let mut hits = BTreeMap::<String, u32>::new();
                for entry in self.verdicts(uid)? {
                    stats.total += 1;
                    match entry.level {
                        Level::None => {}
                        Level::Caution => stats.caution += 1,
                        Level::Danger => stats.danger += 1,
                    }
                    for cue in entry.cues {
                        *hits.entry(cue).or_default() += 1;
                    }
                }
                stats.cues = hits
                    .into_iter()
                    .map(|(cue, hits)| CueCount { cue, hits })
                    .collect();
                Ok(PhishingResponse::Stats(stats))
            }
        }
    }

    /// Queues the check's verdict-log row unless the uid has reached the day's cap, and answers.
    fn verdict(
        &self,
        uid: u32,
        mode: Mode,
        kind: ObservationKind,
        msg: u64,
        assessment: Assessment,
        now_ms: u64,
    ) -> Result<PhishingResponse, String> {
        let show = mode == Mode::Warn && assessment.level != Level::None;
        let day = now_ms / DAY_MS;
        let mut logged = lock(&self.logged)?;
        let (logged_day, count) = logged.entry(uid).or_default();
        if *logged_day != day {
            (*logged_day, *count) = (day, 0);
        }
        // The store refuses a non-finite score, and with it the whole batch.
        if *count < DAILY_LOG_CAP && assessment.score.is_finite() {
            *count += 1;
            let entry = VerdictEntry {
                time_ms: now_ms,
                kind,
                domain: assessment.domain,
                cues: assessment.cues.iter().map(|cue| cue.id().into()).collect(),
                score: assessment.score,
                level: assessment.level,
                shown: show,
            };
            self.queue(PhishingWrite::Verdict { uid, msg, entry });
        }
        Ok(PhishingResponse::Verdict(PhishingVerdict {
            level: assessment.level,
            reasons: assessment.reasons,
            show,
        }))
    }

    /// Rewrites only the `mode` value in the policy file, keeping every comment and every other
    /// byte, and applies the file as rewritten. A file that would not load is left alone.
    fn set_mode(&self, mode: Mode) -> Result<PhishingResponse, String> {
        let path = &self.policy_path;
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|_| format!("{} is not valid TOML", path.display()))?;
        let value = doc
            .get_mut("mode")
            .and_then(toml_edit::Item::as_value_mut)
            .ok_or_else(|| format!("{} has no mode value", path.display()))?;
        let decor = value.decor().clone();
        *value = match mode {
            Mode::Off => "off",
            Mode::Monitor => "monitor",
            Mode::Warn => "warn",
        }
        .into();
        *value.decor_mut() = decor;
        let updated = doc.to_string();
        let policy = Policy::from_toml(&updated)
            .map_err(|e| format!("{} would not load: {e}", path.display()))?;

        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &updated)
            .and_then(|()| std::fs::rename(&tmp, path))
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        self.policy.send_replace(Arc::new(policy));
        info!(?mode, path = %path.display(), "phishing mode set");
        Ok(PhishingResponse::Ok)
    }

    /// The uid's logged checks, newest first, one per `msg`.
    fn verdicts(&self, uid: u32) -> Result<Vec<VerdictEntry>, String> {
        let rows = self
            .store
            .phishing_verdicts(uid, usize::MAX)
            .map_err(|e| format!("reading the verdict log: {e}"))?;
        let mut seen = HashSet::new();
        Ok(rows
            .into_iter()
            .filter(|row| seen.insert(row.msg))
            .map(|row| row.entry)
            .collect())
    }

    fn queue(&self, write: PhishingWrite) {
        if let Err(e) = self.writes.try_send(write) {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(dropped, reason = %e, "phishing write not queued; dropped");
            }
        }
    }
}

impl PhishingQuery for PhishingAdapter {
    fn handle(&self, uid: u32, request: PhishingRequest) -> PhishingResponse {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let answer = || {
            self.answer(uid, request, now_ms)
                .unwrap_or_else(PhishingResponse::Error)
        };
        // The engine computes and may wait for this user's lock. On a multi-thread runtime (the
        // daemon's) the worker hands its other tasks to another thread meanwhile; on a
        // current-thread runtime `block_in_place` panics, and there is no other thread anyway.
        match Handle::try_current().map(|runtime| runtime.runtime_flavor()) {
            Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(answer),
            _ => answer(),
        }
    }
}

/// Commits queued writes, one transaction per batch, on the blocking pool (a commit fsyncs).
/// Returns once every sender is gone and the queue is empty, so an orderly shutdown stores
/// everything queued.
pub async fn write_batches(store: Arc<RiggsStore>, mut queue: mpsc::Receiver<PhishingWrite>) {
    let mut batch = Vec::with_capacity(BATCH_MAX);
    while queue.recv_many(&mut batch, BATCH_MAX).await > 0 {
        let writes = std::mem::take(&mut batch);
        let count = writes.len();
        let store = Arc::clone(&store);
        match tokio::task::spawn_blocking(move || store.phishing_apply(&writes)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(error = %e, count, "phishing batch not stored; dropped"),
            Err(e) => error!(error = %e, count, "phishing store task failed; batch dropped"),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|_| "phishing state lock poisoned".to_string())
}

fn login_entry(row: &LoginRow) -> LoginEntry {
    LoginEntry {
        domain: row.domain.clone(),
        first_ms: row.first_ms,
        last_ms: row.last_ms,
        count: row.count,
    }
}

fn write(uid: u32, change: Change) -> PhishingWrite {
    match change {
        Change::Login(row) => PhishingWrite::Login {
            uid,
            entry: login_entry(&row),
        },
        Change::LoginRemoved(domain) => PhishingWrite::ForgetLogin { uid, domain },
        Change::Sender(row) => PhishingWrite::Sender {
            uid,
            entry: SenderEntry {
                key: row.key,
                first_ms: row.first_ms,
                first_msg: row.first_msg,
            },
        },
    }
}

/// Page checks of one site on one UTC day share a `msg`, so reading the log collapses them.
/// The "page" tag keeps it apart from every mail fingerprint, whose tags are provider names.
fn page_fingerprint(domain: &str, day: u64) -> u64 {
    let digest = Sha256::new()
        .chain_update(b"page\0")
        .chain_update(domain)
        .chain_update(day.to_be_bytes())
        .finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use riggs_comms::{ClientMessage, DaemonMessage, DaemonState, IpcClient, IpcServer};
    use riggs_types::phishing::{
        Evidence, Link, LoginObservation, MailObservation, PageObservation, Provider,
    };
    use std::path::Path;
    use std::sync::atomic::AtomicBool;
    use std::sync::Barrier;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc::error::TryRecvError;

    const SHIPPED: &str = include_str!("../../../config/phishing-policy.toml");
    const UID: u32 = 501;
    const HOUR: u64 = 60 * 60 * 1000;
    /// 10:00 UTC on a fixed day.
    const T0: u64 = 20_000 * DAY_MS + 10 * HOUR;

    fn policy_text(mode: &str) -> String {
        let text = SHIPPED.replacen("mode = \"monitor\"", &format!("mode = \"{mode}\""), 1);
        assert!(text.contains(&format!("mode = \"{mode}\"")));
        text
    }

    fn adapter_in(dir: &Path, capacity: usize) -> (PhishingAdapter, mpsc::Receiver<PhishingWrite>) {
        let store = Arc::new(RiggsStore::new(&dir.join("riggs.db")).unwrap());
        let path = dir.join("phishing-policy.toml");
        let policy = riggs_phishing::reload::load_policy_file(&path).unwrap();
        let policy = Arc::new(watch::Sender::new(Arc::new(policy)));
        PhishingAdapter::new(store, policy, path, capacity).unwrap()
    }

    /// A temporary directory holding a store and the shipped policy in `mode`.
    fn setup(
        mode: &str,
        capacity: usize,
    ) -> (PathBuf, PhishingAdapter, mpsc::Receiver<PhishingWrite>) {
        let dir =
            std::env::temp_dir().join(format!("riggs-phishing-adapter-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("phishing-policy.toml"), policy_text(mode)).unwrap();
        let (adapter, queue) = adapter_in(&dir, capacity);
        (dir, adapter, queue)
    }

    fn ask(
        adapter: &PhishingAdapter,
        uid: u32,
        request: PhishingRequest,
        now_ms: u64,
    ) -> PhishingResponse {
        adapter
            .answer(uid, request, now_ms)
            .unwrap_or_else(PhishingResponse::Error)
    }

    /// Commits what is queued, as the writer task does.
    fn flush(adapter: &PhishingAdapter, queue: &mut mpsc::Receiver<PhishingWrite>) {
        let mut writes = Vec::new();
        while let Ok(write) = queue.try_recv() {
            writes.push(write);
        }
        adapter.store.phishing_apply(&writes).unwrap();
    }

    fn mail(from_addr: &str, message_id: &str, href: &str) -> PhishingRequest {
        PhishingRequest::CheckMail(Box::new(MailObservation {
            provider: Provider::Gmail,
            message_id: message_id.into(),
            from_name: "Constructed Sender".into(),
            from_addr: from_addr.into(),
            reply_to: None,
            to: vec![],
            subject: "Constructed subject".into(),
            body_text: "Constructed body".into(),
            links: vec![Link {
                text: "Sign in".into(),
                href: href.into(),
            }],
            attachments: vec![],
            truncated: false,
        }))
    }

    fn page(host: &str, opened_from_mail: bool) -> PhishingRequest {
        PhishingRequest::CheckPage(PageObservation {
            host: host.into(),
            entry_host: None,
            opened_from_mail,
            mail_level: None,
        })
    }

    fn login(host: &str) -> PhishingRequest {
        PhishingRequest::LoginSeen(LoginObservation {
            host: host.into(),
            evidence: Evidence::Typed,
        })
    }

    fn trust(uid: u32, domain: &str) -> PhishingRequest {
        PhishingRequest::Trust {
            uid,
            domain: domain.into(),
        }
    }

    fn logins(adapter: &PhishingAdapter, uid: u32) -> Vec<String> {
        match ask(adapter, uid, PhishingRequest::Logins { uid }, T0) {
            PhishingResponse::Logins(logins) => logins.into_iter().map(|l| l.domain).collect(),
            other => panic!("{other:?}"),
        }
    }

    fn recent(adapter: &PhishingAdapter, caller: u32, uid: u32) -> Vec<VerdictEntry> {
        match ask(
            adapter,
            caller,
            PhishingRequest::Recent { uid, limit: 50 },
            T0,
        ) {
            PhishingResponse::Recent(entries) => entries,
            other => panic!("{other:?}"),
        }
    }

    fn mode(adapter: &PhishingAdapter) -> Mode {
        match ask(adapter, UID, PhishingRequest::Status, T0) {
            PhishingResponse::Status(status) => status.mode,
            other => panic!("{other:?}"),
        }
    }

    fn queued_verdicts(queue: &mut mpsc::Receiver<PhishingWrite>) -> usize {
        std::iter::from_fn(|| queue.try_recv().ok())
            .filter(|write| matches!(write, PhishingWrite::Verdict { .. }))
            .count()
    }

    #[tokio::test]
    async fn a_second_adapter_over_the_same_store_knows_logins_senders_and_verdicts() {
        let (dir, adapter, queue) = setup("monitor", QUEUE_CAPACITY);
        let writer = tokio::spawn(write_batches(Arc::clone(&adapter.store), queue));
        assert_eq!(
            ask(&adapter, UID, login("www.example.com"), T0),
            PhishingResponse::Ok
        );
        ask(
            &adapter,
            UID,
            mail("news@example.net", "m1", "https://example.net/"),
            T0,
        );
        // The adapter holds the queue's only sender: dropping it lets the writer drain and exit.
        drop(adapter);
        writer.await.unwrap();

        let (adapter, mut queue) = adapter_in(&dir, QUEUE_CAPACITY);
        assert_eq!(logins(&adapter, UID), ["example.com"]);
        let first = recent(&adapter, UID, UID);
        assert_eq!(first.len(), 1);
        assert!(first[0].cues.contains(&"sender_never_seen".to_string()));
        ask(
            &adapter,
            UID,
            mail("news@example.net", "m2", "https://example.net/"),
            T0 + 1,
        );
        flush(&adapter, &mut queue);
        let both = recent(&adapter, UID, UID);
        assert_eq!(both.len(), 2);
        assert!(!both[0].cues.contains(&"sender_never_seen".to_string()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stored_login_that_is_no_longer_registrable_is_skipped_and_the_rest_load() {
        let (dir, adapter, _queue) = setup("monitor", 8);
        let row = |domain: &str| PhishingWrite::Login {
            uid: UID,
            entry: LoginEntry {
                domain: domain.into(),
                first_ms: 1,
                last_ms: 1,
                count: 1,
            },
        };
        // "www.example.com" stands for a row whose domain the public-suffix data reclassified.
        let rows = [row("www.example.com"), row("example.org")];
        adapter.store.phishing_apply(&rows).unwrap();
        drop(adapter);

        let (adapter, _queue) = adapter_in(&dir, 8);
        assert_eq!(logins(&adapter, UID), ["example.org"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_mode_changes_the_one_value_and_the_adapter_reports_it() {
        let (dir, adapter, _queue) = setup("monitor", 8);
        let path = dir.join("phishing-policy.toml");
        let set = |mode| ask(&adapter, UID, PhishingRequest::SetMode { mode }, T0);

        assert_eq!(set(Mode::Warn), PhishingResponse::Ok);
        let written = std::fs::read_to_string(&path).unwrap();
        // The shipped line carries a trailing comment, which must survive too.
        assert_eq!(written, policy_text("warn"));
        assert_eq!(mode(&adapter), Mode::Warn);

        std::fs::write(&path, "mode = [").unwrap();
        assert!(matches!(set(Mode::Off), PhishingResponse::Error(_)));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mode = [");
        assert_eq!(mode(&adapter), Mode::Warn);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mode_off_evaluates_records_and_queues_nothing() {
        let (dir, adapter, mut queue) = setup("off", 8);
        assert_eq!(
            ask(&adapter, UID, trust(UID, "amazon.com"), T0),
            PhishingResponse::Ok
        );
        assert!(queue.try_recv().is_ok());
        let state = |a: &PhishingAdapter| {
            format!(
                "{:?} {:?}",
                a.users.lock().unwrap(),
                a.logged.lock().unwrap()
            )
        };
        let before = state(&adapter);

        let quiet = PhishingResponse::Verdict(PhishingVerdict {
            level: Level::None,
            reasons: vec![],
            show: false,
        });
        // Each of these is a lookalike of amazon.com.
        let checked = mail("orders@amazan.com", "m1", "https://amazan.com/");
        assert_eq!(ask(&adapter, UID, checked, T0), quiet);
        assert_eq!(ask(&adapter, UID, page("amazan.com", true), T0), quiet);
        assert_eq!(
            ask(&adapter, UID, login("amazan.com"), T0),
            PhishingResponse::Ok
        );

        assert_eq!(state(&adapter), before);
        assert!(matches!(queue.try_recv(), Err(TryRecvError::Empty)));
        assert!(adapter.store.phishing_verdicts(UID, 10).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_observations_are_refused_without_echoing_them() {
        let (dir, adapter, mut queue) = setup("warn", 8);
        let long = "q".repeat(4097);
        let mut long_mail = mail("a@example.com", "m1", "https://example.com/");
        if let PhishingRequest::CheckMail(m) = &mut long_mail {
            m.subject = long.clone();
        }
        let requests = [long_mail, page(&long[..256], false), login(&long[..256])];
        for request in requests {
            let PhishingResponse::Error(error) = ask(&adapter, UID, request, T0) else {
                panic!("an oversized observation was answered");
            };
            assert!(error.contains("exceeds its limit"), "{error}");
            assert!(!error.contains("qq"), "{error}");
        }
        assert!(matches!(queue.try_recv(), Err(TryRecvError::Empty)));
        assert!(adapter.users.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_uids_see_only_their_own_logins_verdicts_and_stats() {
        let (dir, adapter, mut queue) = setup("monitor", 64);
        ask(&adapter, 501, login("www.example.com"), T0);
        ask(&adapter, 502, login("www.example.org"), T0);
        ask(
            &adapter,
            501,
            mail("a@example.net", "m1", "https://example.net/"),
            T0,
        );
        ask(&adapter, 502, page("www.example.edu", false), T0);
        flush(&adapter, &mut queue);

        assert_eq!(logins(&adapter, 501), ["example.com"]);
        assert_eq!(logins(&adapter, 502), ["example.org"]);
        // An admin request is about the uid it names, whoever sends it.
        for caller in [501, 502] {
            let mine = recent(&adapter, caller, 501);
            let theirs = recent(&adapter, caller, 502);
            assert_eq!(
                mine.iter()
                    .map(|e| (e.kind, e.domain.as_str()))
                    .collect::<Vec<_>>(),
                [(ObservationKind::Mail, "example.net")]
            );
            assert_eq!(
                theirs
                    .iter()
                    .map(|e| (e.kind, e.domain.as_str()))
                    .collect::<Vec<_>>(),
                [(ObservationKind::Page, "example.edu")]
            );
        }
        let stats = |uid| match ask(&adapter, UID, PhishingRequest::Stats { uid }, T0) {
            PhishingResponse::Stats(stats) => stats,
            other => panic!("{other:?}"),
        };
        let (mail_stats, page_stats) = (stats(501), stats(502));
        assert_eq!((mail_stats.total, page_stats.total), (1, 1));
        assert!(mail_stats.cues.iter().any(|c| c.cue == "sender_never_seen"));
        assert!(page_stats.cues.is_empty());
        assert_eq!(stats(503).total, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn show_follows_the_mode_and_the_level() {
        let (dir, adapter, _queue) = setup("warn", 64);
        // Enough logins for the page context rule, plus the domain the lookalike imitates.
        let warmup = (0..20).map(|i| format!("warmup{i}.org"));
        for domain in warmup.chain(["bankofamerica.com".to_string()]) {
            assert_eq!(
                ask(&adapter, UID, trust(UID, &domain), T0),
                PhishingResponse::Ok
            );
        }
        let check =
            |host: &str, from_mail: bool| match ask(&adapter, UID, page(host, from_mail), T0) {
                PhishingResponse::Verdict(v) => (v.level, v.show),
                other => panic!("{other:?}"),
            };

        assert_eq!(check("www.bankofamerica.com", true), (Level::None, false));
        assert_eq!(check("signup.example.net", true), (Level::Caution, true));
        assert_eq!(
            check("www.bankofarnerica.com", false),
            (Level::Danger, true)
        );

        let monitor = Policy::from_toml(&policy_text("monitor")).unwrap();
        adapter.policy.send_replace(Arc::new(monitor));
        assert_eq!(check("www.bankofamerica.com", true), (Level::None, false));
        assert_eq!(check("signup.example.net", true), (Level::Caution, false));
        assert_eq!(
            check("www.bankofarnerica.com", false),
            (Level::Danger, false)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_full_queue_drops_and_counts_without_waiting() {
        let (dir, adapter, mut queue) = setup("monitor", 1);
        let started = Instant::now();
        assert_eq!(
            adapter.handle(UID, login("www.example.com")),
            PhishingResponse::Ok
        );
        assert_eq!(
            adapter.handle(UID, login("www.example.org")),
            PhishingResponse::Ok
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(adapter.dropped.load(Ordering::Relaxed), 1);
        let domain = |write| match write {
            Ok(PhishingWrite::Login { entry, .. }) => entry.domain,
            other => panic!("{other:?}"),
        };
        assert_eq!(domain(queue.try_recv()), "example.com");

        adapter.handle(UID, login("www.example.net"));
        assert_eq!(domain(queue.try_recv()), "example.net");
        assert_eq!(adapter.dropped.load(Ordering::Relaxed), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_users_held_lock_delays_only_that_user() {
        let (dir, adapter, _queue) = setup("monitor", 64);
        let user_a = adapter.user(501).unwrap();
        let held = user_a.lock().unwrap();
        let released = AtomicBool::new(false);
        let started = Barrier::new(2);
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| {
                started.wait();
                let answer = ask(&adapter, 501, page("www.example.com", false), T0);
                (released.load(Ordering::SeqCst), answer)
            });
            started.wait();
            let other = ask(&adapter, 502, page("www.example.org", false), T0);
            assert!(matches!(other, PhishingResponse::Verdict(_)));
            assert!(!waiting.is_finished());

            released.store(true, Ordering::SeqCst);
            drop(held);
            let (answered_after_release, answer) = waiting.join().unwrap();
            assert!(answered_after_release, "answered while its lock was held");
            assert!(matches!(answer, PhishingResponse::Verdict(_)));
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    async fn handle_answers_in_the_test_body_and_in_a_spawned_task() {
        let (dir, adapter, _queue) = setup("monitor", 8);
        let adapter = Arc::new(adapter);
        let status = |answer| matches!(answer, PhishingResponse::Status(_));
        assert!(status(adapter.handle(UID, PhishingRequest::Status)));
        let spawned = Arc::clone(&adapter);
        let answer = tokio::spawn(async move { spawned.handle(UID, PhishingRequest::Status) });
        assert!(status(answer.await.unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_answers_on_a_multi_thread_runtime() {
        handle_answers_in_the_test_body_and_in_a_spawned_task().await;
    }

    #[tokio::test]
    async fn handle_answers_on_a_current_thread_runtime() {
        handle_answers_in_the_test_body_and_in_a_spawned_task().await;
    }

    #[test]
    fn the_verdict_log_takes_at_most_the_daily_cap() {
        let (dir, adapter, mut queue) = setup("monitor", 2 * DAILY_LOG_CAP as usize);
        for i in 0..=u64::from(DAILY_LOG_CAP) {
            let answer = ask(&adapter, UID, page("www.example.com", false), T0 + i);
            assert!(matches!(answer, PhishingResponse::Verdict(_)));
        }
        assert_eq!(queued_verdicts(&mut queue), DAILY_LOG_CAP as usize);
        ask(&adapter, UID, page("www.example.com", false), T0 + DAY_MS);
        assert_eq!(queued_verdicts(&mut queue), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn page_checks_of_one_site_read_back_as_one_entry_a_day() {
        let (dir, adapter, mut queue) = setup("monitor", 16);
        ask(&adapter, UID, page("www.example.com", false), T0);
        ask(&adapter, UID, page("login.example.com", false), T0 + HOUR);
        flush(&adapter, &mut queue);
        let one = recent(&adapter, UID, UID);
        assert_eq!(
            one.iter()
                .map(|e| (e.domain.as_str(), e.time_ms))
                .collect::<Vec<_>>(),
            [("example.com", T0 + HOUR)]
        );

        ask(&adapter, UID, page("www.example.com", false), T0 + DAY_MS);
        flush(&adapter, &mut queue);
        assert_eq!(recent(&adapter, UID, UID).len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_daemon_socket_answers_with_the_real_adapter() {
        use std::os::unix::fs::MetadataExt;

        let (dir, adapter, queue) = setup("warn", QUEUE_CAPACITY);
        let store = Arc::clone(&adapter.store);
        tokio::spawn(write_batches(Arc::clone(&store), queue));
        let state = Arc::new(DaemonState::new());
        *state.phishing.write().unwrap() = Some(Arc::new(adapter));
        let socket =
            std::env::temp_dir().join(format!("riggs-phishing-{}.sock", std::process::id()));
        let server = IpcServer::with_state(socket.clone(), Arc::clone(&state));
        tokio::spawn(async move { server.start().await });
        while !socket.exists() {
            tokio::task::yield_now().await;
        }
        let send = |request: PhishingRequest| {
            let socket = socket.clone();
            async move {
                let mut client = IpcClient::connect(&socket).await.unwrap();
                match client
                    .send(&ClientMessage::Phishing(request))
                    .await
                    .unwrap()
                {
                    DaemonMessage::Phishing(response) => response,
                    other => panic!("{other:?}"),
                }
            }
        };
        // In-process the peer is this test, so the daemon keys sensor requests by our own uid.
        let me = std::fs::metadata(&dir).unwrap().uid();

        assert_eq!(send(trust(me, "microsoft.com")).await, PhishingResponse::Ok);
        let lookalike = mail(
            "notice@example.net",
            "msg-0001",
            "https://micorsoft-support.com/signin",
        );
        let PhishingResponse::Verdict(verdict) = send(lookalike).await else {
            panic!("no verdict for the mail");
        };
        assert_eq!((verdict.level, verdict.show), (Level::Danger, true));

        assert_eq!(send(login("login.example.org")).await, PhishingResponse::Ok);
        let PhishingResponse::Verdict(verdict) = send(page("login.example.org", true)).await else {
            panic!("no verdict for the page");
        };
        assert_eq!((verdict.level, verdict.show), (Level::None, false));

        for _ in 0..500 {
            if store.phishing_verdicts(me, 10).unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let recent = send(PhishingRequest::Recent { uid: me, limit: 10 }).await;
        let PhishingResponse::Recent(entries) = &recent else {
            panic!("{recent:?}");
        };
        let logged: Vec<_> = entries
            .iter()
            .map(|e| (e.kind, e.domain.as_str(), e.level, e.shown))
            .collect();
        assert_eq!(
            logged,
            [
                (ObservationKind::Page, "example.org", Level::None, false),
                (ObservationKind::Mail, "example.net", Level::Danger, true),
            ]
        );
        assert!(entries[1]
            .cues
            .contains(&"domain_lookalike_misspelling".to_string()));
        let json = serde_json::to_string(&recent).unwrap();
        for content in [
            "notice",
            "micorsoft",
            "signin",
            "Constructed",
            "msg-0001",
            "Sign in",
        ] {
            assert!(!json.contains(content), "{content} leaked into {json}");
        }

        // The privilege gate itself (`needs_privilege`) is private to riggs-comms and tested
        // there; it gates a phishing request exactly when `is_admin` holds.
        let admin = [
            PhishingRequest::SetMode { mode: Mode::Warn },
            trust(me, "example.com"),
            PhishingRequest::Forget {
                uid: me,
                domain: "example.com".into(),
            },
            PhishingRequest::Logins { uid: me },
            PhishingRequest::Recent { uid: me, limit: 1 },
            PhishingRequest::Stats { uid: me },
        ];
        assert!(admin.iter().all(PhishingRequest::is_admin));
        std::fs::remove_file(&socket).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
