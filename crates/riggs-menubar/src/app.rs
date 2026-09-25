#![cfg(target_os = "macos")]

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Sel};
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_app_kit::{NSApplication, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem};
use objc2_foundation::{MainThreadMarker, NSObject, NSString};
use tracing::info;

use crate::poller::trigger_scan_background;
use crate::status::SharedStatus;

const DEFAULT_TIMER_INTERVAL_SECS: f64 = 2.0;

/// Menu refresh cadence, overridable via RIGGS_MENUBAR_TIMER_SECS.
fn timer_interval_secs() -> f64 {
    std::env::var("RIGGS_MENUBAR_TIMER_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&s| s > 0.0)
        .unwrap_or(DEFAULT_TIMER_INTERVAL_SECS)
}

struct DelegateIvars {
    status: SharedStatus,
    status_item: Option<Retained<NSStatusItem>>,
    status_menu_item: Option<Retained<NSMenuItem>>,
    threats_menu_item: Option<Retained<NSMenuItem>>,
    events_menu_item: Option<Retained<NSMenuItem>>,
    intel_menu_item: Option<Retained<NSMenuItem>>,
    feeds_menu_item: Option<Retained<NSMenuItem>>,
}

// Safety: SharedStatus is Arc<Mutex<...>> which is Send+Sync.
// The Retained<NS*> types are only accessed on the main thread.
unsafe impl Send for DelegateIvars {}
unsafe impl Sync for DelegateIvars {}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "RiggsAppDelegate"]
    #[ivars = DelegateIvars]
    struct AppDelegate;

    impl AppDelegate {
        #[unsafe(method(scanNow:))]
        fn _scan_now(&self, _sender: *mut AnyObject) {
            info!("scan now triggered from menu");
            trigger_scan_background("/".to_string());
        }

        #[unsafe(method(openTerminal:))]
        fn _open_terminal(&self, _sender: *mut AnyObject) {
            info!("opening Terminal.app");
            let _ = std::process::Command::new("open")
                .arg("-a")
                .arg("Terminal")
                .spawn();
        }

        #[unsafe(method(quitApp:))]
        fn _quit_app(&self, _sender: *mut AnyObject) {
            info!("quit requested");
            let mtm = MainThreadMarker::from(self);
            let app = NSApplication::sharedApplication(mtm);
            app.terminate(None);
        }

        #[unsafe(method(updateMenu:))]
        fn _update_menu(&self, _timer: *mut AnyObject) {
            let ivars = self.ivars();
            let status = ivars.status.lock().unwrap_or_else(|e| e.into_inner());

            let (title_char, status_text) = if !status.connected {
                ("R!", "Disconnected from daemon".to_string())
            } else if status.active_threats > 0 {
                ("R!", format!("{} threat{} detected", status.active_threats,
                    if status.active_threats == 1 { "" } else { "s" }))
            } else if status.running {
                ("R", "Protected".to_string())
            } else {
                ("R?", "Daemon not running".to_string())
            };

            let threats_text = if status.active_threats > 0 {
                format!("\u{26A0}\u{FE0F}  {} active threat{}", status.active_threats,
                    if status.active_threats == 1 { "" } else { "s" })
            } else {
                "\u{2705}  No active threats".to_string()
            };

            let events_text = format!("\u{1F4CA}  {} events processed", format_count(status.events_processed));

            let intel_text = if status.bloom_size > 0 || status.cache_entries > 0 {
                format!("\u{1F50D}  {} hashes | {} IOC cache entries",
                    format_count(status.bloom_size as u64),
                    format_count(status.cache_entries))
            } else {
                "\u{1F50D}  Intel: loading...".to_string()
            };

            let feeds_text = match &status.feeds_last_updated {
                Some(ts) => format!("\u{1F4E1}  Feeds updated: {}", ts),
                None => "\u{1F4E1}  Feeds: active".to_string(),
            };

            let mtm = MainThreadMarker::from(self);

            // Update status bar button title
            if let Some(ref status_item) = ivars.status_item {
                if let Some(button) = status_item.button(mtm) {
                    button.setTitle(&NSString::from_str(title_char));
                }
            }

            // Update menu items
            if let Some(ref item) = ivars.status_menu_item {
                item.setTitle(&NSString::from_str(&status_text));
            }
            if let Some(ref item) = ivars.threats_menu_item {
                item.setTitle(&NSString::from_str(&threats_text));
            }
            if let Some(ref item) = ivars.events_menu_item {
                item.setTitle(&NSString::from_str(&events_text));
            }
            if let Some(ref item) = ivars.intel_menu_item {
                item.setTitle(&NSString::from_str(&intel_text));
            }
            if let Some(ref item) = ivars.feeds_menu_item {
                item.setTitle(&NSString::from_str(&feeds_text));
            }
        }
    }
);

impl AppDelegate {
    fn new(mtm: MainThreadMarker, status: SharedStatus) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(DelegateIvars {
            status,
            status_item: None,
            status_menu_item: None,
            threats_menu_item: None,
            events_menu_item: None,
            intel_menu_item: None,
            feeds_menu_item: None,
        });
        unsafe { msg_send![super(this), init] }
    }
}

pub fn run_app(status: SharedStatus) {
    let mtm = MainThreadMarker::new().expect("must run on main thread");

    let app = NSApplication::sharedApplication(mtm);

    let delegate = AppDelegate::new(mtm, status);

    // Create status bar item
    let status_bar = NSStatusBar::systemStatusBar();
    let status_item = status_bar.statusItemWithLength(-1.0);

    // Set initial title on the button
    if let Some(button) = status_item.button(mtm) {
        button.setTitle(&NSString::from_str("R"));
    }

    // Build menu
    let menu = build_menu(mtm, &delegate);
    status_item.setMenu(Some(&menu));

    // Store status_item reference in delegate ivars.
    // Safety: we are on the main thread, and the delegate is exclusively owned at this point.
    let ivars_ptr = delegate.ivars() as *const DelegateIvars as *mut DelegateIvars;
    unsafe {
        (*ivars_ptr).status_item = Some(status_item);
    }

    // Set up a timer to update the menu periodically
    setup_update_timer(&delegate);

    info!("riggs menubar app starting");

    // Run the app (blocks forever)
    app.run();
}

fn build_menu(mtm: MainThreadMarker, delegate: &Retained<AppDelegate>) -> Retained<NSMenu> {
    let menu = NSMenu::new(mtm);

    // Header
    let header = make_disabled_item(mtm, "Riggs Endpoint Protection");
    menu.addItem(&header);

    // Separator
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    // Status items (disabled, updated by timer)
    let status_item = make_disabled_item(mtm, "Connecting...");
    let threats_item = make_disabled_item(mtm, "\u{2705}  No active threats");
    let events_item = make_disabled_item(mtm, "\u{1F4CA}  0 events processed");

    menu.addItem(&status_item);
    menu.addItem(&threats_item);
    menu.addItem(&events_item);

    // Separator
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    // Intel section
    let intel_item = make_disabled_item(mtm, "\u{1F50D}  Intel: loading...");
    let feeds_item = make_disabled_item(mtm, "\u{1F4E1}  Feeds: loading...");
    menu.addItem(&intel_item);
    menu.addItem(&feeds_item);

    // Store references for updating
    let ivars_ptr = delegate.ivars() as *const DelegateIvars as *mut DelegateIvars;
    unsafe {
        (*ivars_ptr).status_menu_item = Some(status_item);
        (*ivars_ptr).threats_menu_item = Some(threats_item);
        (*ivars_ptr).events_menu_item = Some(events_item);
        (*ivars_ptr).intel_menu_item = Some(intel_item);
        (*ivars_ptr).feeds_menu_item = Some(feeds_item);
    }

    // Separator
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    // Scan Now
    let scan_item = make_action_item(mtm, "Scan Now", sel!(scanNow:), delegate);
    menu.addItem(&scan_item);

    // Open Terminal
    let terminal_item = make_action_item(mtm, "Open Terminal", sel!(openTerminal:), delegate);
    menu.addItem(&terminal_item);

    // Separator
    menu.addItem(&NSMenuItem::separatorItem(mtm));

    // Quit
    let quit_item = make_action_item(mtm, "Quit Riggs", sel!(quitApp:), delegate);
    menu.addItem(&quit_item);

    menu
}

fn make_disabled_item(mtm: MainThreadMarker, title: &str) -> Retained<NSMenuItem> {
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc::<NSMenuItem>(),
            &NSString::from_str(title),
            None,
            &NSString::from_str(""),
        )
    };
    item.setEnabled(false);
    item
}

fn make_action_item(
    mtm: MainThreadMarker,
    title: &str,
    action: Sel,
    target: &Retained<AppDelegate>,
) -> Retained<NSMenuItem> {
    let item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc::<NSMenuItem>(),
            &NSString::from_str(title),
            Some(action),
            &NSString::from_str(""),
        )
    };
    unsafe {
        item.setTarget(Some(target.as_ref() as &AnyObject));
    }
    item
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn setup_update_timer(delegate: &Retained<AppDelegate>) {
    unsafe {
        let _timer =
            objc2_foundation::NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                timer_interval_secs(),
                delegate.as_ref() as &AnyObject,
                sel!(updateMenu:),
                None,
                true,
            );
        // Timer is retained by the run loop, no need to keep a reference
    }
}
