//! Process attribution for file events via fanotify (Linux, needs CAP_SYS_ADMIN).
//!
//! Classic (fd-reporting) fanotify marks the mounts holding the watched directories
//! and reports opens and finished writes with the acting pid. It cannot report
//! creates, deletes, renames or attribute changes, so inotify still does; those
//! events pass through here to borrow the pid fanotify last saw on the same file.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use riggs_types::events::{FileAction, ProcessContext, RiggsEvent, StorylineId};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// How long a fanotify sighting attributes inotify events on the same file: long
/// enough for write-then-rename saves, short enough not to blame a stale writer.
const ATTRIBUTION_WINDOW: Duration = Duration::from_secs(2);
/// open(2) queues IN_CREATE before FAN_OPEN, so inotify can report a create first.
const CREATE_RACE: Duration = Duration::from_millis(20);
/// Where Open events are emitted. Opens under /etc and /usr/bin (every exec and
/// libc lookup) dwarf the rest and say nothing about the user data DLP correlates.
const OPEN_DIRS: &[&str] = &["/home", "/tmp"];

/// Inode keys survive renames; path keys cover files renamed away or deleted.
#[derive(Hash, PartialEq, Eq)]
enum Key {
    Inode(u64, u64),
    Path(PathBuf),
}

/// A process fanotify saw open or finish writing a watched file.
struct Sighting {
    inode: Key,
    path: Key,
    ctx: ProcessContext,
}

type Sightings = HashMap<Key, (ProcessContext, Instant)>;

/// Ids of the mounts fanotify marked. inotify's per-write events are redundant
/// only on these; on a mount fanotify could not mark, inotify's event is the
/// only one, so it is kept (without a pid).
pub(crate) struct Marked(HashSet<u64>);

impl Marked {
    pub(crate) fn covers(&self, path: &Path) -> bool {
        mount_id(path).is_some_and(|id| self.0.contains(&id))
    }
}

/// Starts fanotify on the mounts holding `dirs` and every mount below them, and
/// returns the sender inotify events must go through to be attributed plus the
/// marked mounts, or None (with one warning) when fanotify is unavailable and
/// inotify events stay unattributed.
pub(crate) fn start(
    dirs: &'static [&'static str],
    tx: mpsc::Sender<RiggsEvent>,
) -> Option<(mpsc::Sender<RiggsEvent>, Marked)> {
    // A watched root may be a symlink (/home -> /var/home on Fedora Atomic) and
    // fanotify reports resolved paths: match those, report the configured path
    // as inotify does.
    let roots: Vec<(PathBuf, &'static str)> = dirs
        .iter()
        .filter_map(|d| Some((std::fs::canonicalize(d).ok()?, *d)))
        .collect();
    let (fd, marked) = match init(&roots) {
        Ok(init) => init,
        Err(e) => {
            warn!(error = %e, "fanotify unavailable; file events fall back to inotify without process attribution");
            return None;
        }
    };
    info!("fanotify attributing file events to processes");
    let (sighting_tx, mut sighting_rx) = mpsc::channel::<Sighting>(1024);
    let reader_tx = tx.clone();
    std::thread::spawn(move || read_events(&fd, &roots, &sighting_tx, &reader_tx));

    let (inotify_tx, mut inotify_rx) = mpsc::channel::<RiggsEvent>(1024);
    tokio::spawn(async move {
        let mut seen = Sightings::new();
        let mut prune = tokio::time::interval(ATTRIBUTION_WINDOW);
        loop {
            let mut event = tokio::select! {
                biased;
                Some(sighting) = sighting_rx.recv() => {
                    remember(&mut seen, sighting);
                    continue;
                }
                Some(event) = inotify_rx.recv() => event,
                _ = prune.tick() => {
                    seen.retain(|_, (_, at)| at.elapsed() < ATTRIBUTION_WINDOW);
                    continue;
                }
            };
            if let RiggsEvent::File(fe) = &mut event {
                let (path, action) = (PathBuf::from(&fe.path), fe.action);
                if action == FileAction::Create && !path.is_dir() {
                    let _ = tokio::time::timeout(CREATE_RACE, async {
                        while attribution(&seen, &path, action).is_none() {
                            let Some(sighting) = sighting_rx.recv().await else {
                                break;
                            };
                            remember(&mut seen, sighting);
                        }
                    })
                    .await;
                }
                if let Some(ctx) = attribution(&seen, &path, action) {
                    fe.process_context = ctx;
                }
            }
            if tx.send(event).await.is_err() {
                return;
            }
        }
    });
    Some((inotify_tx, marked))
}

fn init(roots: &[(PathBuf, &str)]) -> io::Result<(OwnedFd, Marked)> {
    // O_NONBLOCK: the kernel opens each event's file into our fd table, and a
    // blocking open of a FIFO would stall the reader.
    let event_flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_LARGEFILE | libc::O_CLOEXEC;
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC,
            event_flags as u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mark = |path: &Path| -> io::Result<()> {
        let path = CString::new(path.as_os_str().as_encoded_bytes())?;
        // A mount mark sees the whole mount; read_events filters back down to `roots`.
        let ret = unsafe {
            libc::fanotify_mark(
                fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                libc::FAN_OPEN | libc::FAN_CLOSE_WRITE,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    let mut marked = HashSet::new();
    for (root, _) in roots {
        mark(root)?;
        marked.extend(mount_id(root));
    }
    // A mount mark stops at child mounts (a separately mounted /home/alice), so
    // mark those too. One that can't be marked stays inotify-only.
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    for point in mountinfo.lines().filter_map(|line| line.split(' ').nth(4)) {
        let point = Path::new(point);
        if roots.iter().any(|(root, _)| point.starts_with(root)) && mark(point).is_ok() {
            marked.extend(mount_id(point));
        }
    }
    Ok((fd, Marked(marked)))
}

/// The id of the mount `path` lives on (statx STATX_MNT_ID, Linux 5.8+).
fn mount_id(path: &Path) -> Option<u64> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    (ret == 0 && stx.stx_mask & libc::STATX_MNT_ID != 0).then_some(stx.stx_mnt_id)
}

fn read_events(
    fd: &OwnedFd,
    roots: &[(PathBuf, &str)],
    sightings: &mpsc::Sender<Sighting>,
    tx: &mpsc::Sender<RiggsEvent>,
) {
    let own_pid = std::process::id();
    // Every event in a read holds an fd until processed; keep batches well under
    // RLIMIT_NOFILE.
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            // The kernel drops an event whose file it cannot open and reports why here.
            if e.kind() != io::ErrorKind::Interrupted {
                warn!(error = %e, "fanotify event lost");
            }
            continue;
        }
        let mut offset = 0;
        while offset + size_of::<libc::fanotify_event_metadata>() <= n as usize {
            let meta: libc::fanotify_event_metadata =
                unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast()) };
            offset += meta.event_len as usize;
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                warn!(
                    version = meta.vers,
                    "unknown fanotify event format; attribution stopped"
                );
                return;
            }
            if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                warn!("fanotify queue overflowed; file events were lost");
                continue;
            }
            if meta.fd < 0 {
                continue;
            }
            let file = File::from(unsafe { OwnedFd::from_raw_fd(meta.fd) });
            let pid = meta.pid as u32;
            if pid == own_pid {
                continue;
            }
            let Ok(link) = std::fs::read_link(format!("/proc/self/fd/{}", meta.fd)) else {
                continue;
            };
            let Some((root, shown)) = roots.iter().find(|(root, _)| link.starts_with(root)) else {
                continue;
            };
            let Ok(stat) = file.metadata() else {
                continue;
            };
            let link = link.to_string_lossy();
            // The kernel suffixes the path of a file unlinked since it was opened.
            let real = match stat.nlink() {
                0 => link.strip_suffix(" (deleted)").unwrap_or(&link),
                _ => &link,
            };
            let path =
                Path::new(shown).join(Path::new(real).strip_prefix(root).unwrap_or(Path::new("")));
            let path = &*path.to_string_lossy();
            let ctx = crate::sensor::proc_context(pid).unwrap_or_else(|| {
                ProcessContext::new(
                    pid,
                    0,
                    "unknown",
                    "unknown",
                    "",
                    "unknown",
                    StorylineId::new(),
                )
            });
            let sighting = Sighting {
                inode: Key::Inode(stat.dev(), stat.ino()),
                path: Key::Path(path.into()),
                ctx: ctx.clone(),
            };
            if sightings.blocking_send(sighting).is_err() {
                return;
            }
            let opened = meta.mask & libc::FAN_OPEN != 0
                && OPEN_DIRS.iter().any(|d| Path::new(path).starts_with(d));
            let written = meta.mask & libc::FAN_CLOSE_WRITE != 0;
            for action in [
                opened.then_some(FileAction::Open),
                written.then_some(FileAction::Modify),
            ]
            .into_iter()
            .flatten()
            {
                let event = RiggsEvent::new_file(action, ctx.clone(), path, None);
                if tx.blocking_send(event).is_err() {
                    return;
                }
            }
        }
    }
}

fn remember(seen: &mut Sightings, sighting: Sighting) {
    let now = Instant::now();
    seen.insert(sighting.inode, (sighting.ctx.clone(), now));
    seen.insert(sighting.path, (sighting.ctx, now));
}

/// The process fanotify last saw on the file an inotify event names. Deletes are
/// never attributed: nothing ties an unlink to an earlier opener.
fn attribution(seen: &Sightings, path: &Path, action: FileAction) -> Option<ProcessContext> {
    if action == FileAction::Delete {
        return None;
    }
    let fresh = |key: &Key| {
        seen.get(key)
            .filter(|(_, at)| at.elapsed() < ATTRIBUTION_WINDOW)
    };
    // While the file exists only a sighting of this very inode names its process:
    // a path sighting may be of a different file since replaced at that path, and
    // a wrong pid is worse than none (kill/suspend would hit it). The path is
    // for files already renamed away.
    match std::fs::symlink_metadata(path) {
        Ok(m) => fresh(&Key::Inode(m.dev(), m.ino())),
        Err(_) => fresh(&Key::Path(path.to_path_buf())),
    }
    .map(|(ctx, _)| ProcessContext {
        storyline_id: StorylineId::new(),
        ..ctx.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer(pid: u32) -> ProcessContext {
        ProcessContext::new(
            pid,
            1,
            "crontab",
            "/usr/bin/crontab",
            "crontab -",
            "1000",
            StorylineId::new(),
        )
    }

    #[test]
    fn attribution_follows_the_writer_across_a_rename_but_never_to_a_delete() {
        let dir = std::env::temp_dir().join(format!("riggs-fanotify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (tmp, dst) = (dir.join("tmp.X"), dir.join("dev"));
        std::fs::write(&tmp, "@reboot /tmp/payload\n").unwrap();
        let stat = std::fs::metadata(&tmp).unwrap();
        let mut seen = Sightings::new();
        remember(
            &mut seen,
            Sighting {
                inode: Key::Inode(stat.dev(), stat.ino()),
                path: Key::Path(tmp.clone()),
                ctx: writer(42),
            },
        );
        seen.insert(
            Key::Path(dir.join("stale")),
            (writer(7), Instant::now() - ATTRIBUTION_WINDOW),
        );
        std::fs::rename(&tmp, &dst).unwrap();

        let pid = |path: &Path, action| attribution(&seen, path, action).map(|ctx| ctx.pid);
        assert_eq!(
            pid(&dst, FileAction::Modify),
            Some(42),
            "new name, by inode"
        );
        assert_eq!(pid(&tmp, FileAction::Modify), Some(42), "old name, by path");
        assert_eq!(pid(&tmp, FileAction::Delete), None);
        assert_eq!(pid(&dir.join("stale"), FileAction::Modify), None);
        assert_eq!(pid(&dir.join("unseen"), FileAction::Create), None);

        // A reader's sighting of the old file must not name the new one put at
        // its path: while a file exists, only its own inode counts.
        std::fs::write(&tmp, "replacement\n").unwrap();
        assert_eq!(pid(&tmp, FileAction::Create), None, "replaced file");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
