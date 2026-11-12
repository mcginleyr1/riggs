//! Chrome native-messaging host for the Riggs browser extension. Chrome starts it
//! once per `sendNativeMessage`: it reads one phishing sensor request, makes one
//! round trip to the daemon and writes one `PhishingResponse`. The contract is
//! docs/PHISHING.md, "The native host". Nothing from a request may reach stderr,
//! which Chrome captures.

use std::path::{Path, PathBuf};
use std::time::Duration;

use riggs_comms::{ClientMessage, DaemonMessage, IpcClient, IpcError};
use riggs_types::phishing::{PhishingRequest, PhishingResponse};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout_at, Instant};

const DEFAULT_SOCKET_PATH: &str = "/var/run/riggs.sock";
const DEADLINE: Duration = Duration::from_secs(5);
/// The daemon's default frame limit (`comms.ipc_max_message_bytes`).
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Chrome's native-messaging docs: "The message length must not exceed 1024*1024."
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// The extension compares this text exactly.
const UNREACHABLE: &str = "daemon unreachable";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let socket = PathBuf::from(
        std::env::var("RIGGS_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string()),
    );
    let written = serve(&mut tokio::io::stdin(), &mut tokio::io::stdout(), &socket).await;
    // A stalled stdin read runs on a thread tokio cannot cancel; exit rather than wait for it.
    std::process::exit(if written.is_ok() { 0 } else { 1 });
}

async fn serve(
    input: &mut (impl AsyncRead + Unpin),
    output: &mut (impl AsyncWrite + Unpin),
    socket: &Path,
) -> std::io::Result<()> {
    let mut body = serde_json::to_vec(&answer(input, socket).await).expect("response serializes");
    if body.len() > MAX_RESPONSE_BYTES {
        body = serde_json::to_vec(&PhishingResponse::Error("daemon answer too large".into()))
            .expect("response serializes");
    }
    output.write_all(&(body.len() as u32).to_ne_bytes()).await?;
    output.write_all(&body).await?;
    output.flush().await
}

async fn answer(input: &mut (impl AsyncRead + Unpin), socket: &Path) -> PhishingResponse {
    let deadline = Instant::now() + DEADLINE;
    let request = match timeout_at(deadline, read_request(input))
        .await
        .unwrap_or(Err("request unreadable"))
    {
        Ok(request) => request,
        Err(refusal) => return PhishingResponse::Error(refusal.into()),
    };
    timeout_at(deadline, ask_daemon(socket, request))
        .await
        .unwrap_or_else(|_| PhishingResponse::Error(UNREACHABLE.into()))
}

/// One frame, admitted only if it is a sensor request in object form. The error
/// texts never quote the input.
async fn read_request(
    input: &mut (impl AsyncRead + Unpin),
) -> Result<PhishingRequest, &'static str> {
    let mut len = [0u8; 4];
    input
        .read_exact(&mut len)
        .await
        .map_err(|_| "request unreadable")?;
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_REQUEST_BYTES {
        return Err("request too large");
    }
    let mut body = vec![0u8; len];
    input
        .read_exact(&mut body)
        .await
        .map_err(|_| "request unreadable")?;
    if body.trim_ascii_start().first() != Some(&b'{') {
        return Err("malformed request");
    }
    match serde_json::from_slice::<PhishingRequest>(&body) {
        Ok(request) if request.is_admin() => Err("request not allowed"),
        Ok(request) => Ok(request),
        Err(_) => Err("malformed request"),
    }
}

async fn ask_daemon(socket: &Path, request: PhishingRequest) -> PhishingResponse {
    let Ok(mut client) = IpcClient::connect(socket).await else {
        return PhishingResponse::Error(UNREACHABLE.into());
    };
    match client.send(&ClientMessage::Phishing(request)).await {
        Ok(DaemonMessage::Phishing(response)) => response,
        Ok(DaemonMessage::Error(_)) => PhishingResponse::Error("daemon refused request".into()),
        Ok(_) | Err(IpcError::Serialization(_) | IpcError::Other(_)) => {
            PhishingResponse::Error("unexpected daemon answer".into())
        }
        Err(IpcError::Io(_)) => PhishingResponse::Error(UNREACHABLE.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    use riggs_comms::{DaemonState, IpcServer, PhishingQuery};
    use riggs_types::phishing::{Level, Mode, PhishingStatus, PhishingVerdict, Reason};

    use super::*;

    /// Records the largest allocation made on each thread, so a test can show that
    /// a claimed frame length was never allocated.
    struct LargestAllocation;

    thread_local! {
        static LARGEST: Cell<usize> = const { Cell::new(0) };
    }

    unsafe impl GlobalAlloc for LargestAllocation {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(layout.size())));
            System.alloc(layout)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout)
        }
    }

    #[global_allocator]
    static ALLOCATOR: LargestAllocation = LargestAllocation;

    struct StubPhishing {
        seen: Mutex<Vec<PhishingRequest>>,
        answer: PhishingResponse,
    }

    impl PhishingQuery for StubPhishing {
        fn handle(&self, _uid: u32, request: PhishingRequest) -> PhishingResponse {
            self.seen.lock().unwrap().push(request);
            self.answer.clone()
        }
    }

    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("riggs-host-{name}-{}.sock", std::process::id()))
    }

    async fn stub_daemon(name: &str, answer: PhishingResponse) -> (PathBuf, Arc<StubPhishing>) {
        let path = socket_path(name);
        let stub = Arc::new(StubPhishing {
            seen: Mutex::default(),
            answer,
        });
        let state = Arc::new(DaemonState::new());
        *state.phishing.write().unwrap() = Some(Arc::clone(&stub) as Arc<dyn PhishingQuery>);
        let server = IpcServer::with_state(path.clone(), state);
        tokio::spawn(async move { server.start().await });
        while !path.exists() {
            tokio::task::yield_now().await;
        }
        (path, stub)
    }

    /// A socket whose connections wait in the backlog and are never served.
    fn silent_socket(name: &str) -> (PathBuf, UnixListener) {
        let path = socket_path(name);
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        (path, listener)
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        [&(body.len() as u32).to_ne_bytes()[..], body].concat()
    }

    async fn run(input: &[u8], socket: &Path) -> Vec<u8> {
        let mut output = Vec::new();
        serve(&mut &input[..], &mut output, socket).await.unwrap();
        output
    }

    fn single_response(output: &[u8]) -> PhishingResponse {
        let len = u32::from_ne_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(output.len(), 4 + len, "exactly one frame");
        serde_json::from_slice(&output[4..]).unwrap()
    }

    #[tokio::test]
    async fn sensor_request_round_trips_through_the_daemon() {
        let request = br#"{"CheckPage":{"host":"example.com","entry_host":"example.org","opened_from_mail":true,"mail_level":"caution"}}"#;
        let answer = PhishingResponse::Verdict(PhishingVerdict {
            level: Level::Caution,
            reasons: vec![Reason {
                cue: "example_cue".into(),
                text: "example reason".into(),
            }],
            show: true,
        });
        let (path, stub) = stub_daemon("round-trip", answer.clone()).await;
        let output = run(&frame(request), &path).await;
        std::fs::remove_file(&path).unwrap();

        assert_eq!(output, frame(&serde_json::to_vec(&answer).unwrap()));
        let seen = stub.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(serde_json::to_vec(&seen[0]).unwrap(), request);
    }

    #[tokio::test]
    async fn status_in_object_form_reaches_the_daemon() {
        let answer = PhishingResponse::Status(PhishingStatus {
            mode: Mode::Monitor,
            logins: 0,
        });
        let (path, stub) = stub_daemon("status", answer.clone()).await;
        let output = run(&frame(br#"{"Status": null}"#), &path).await;
        std::fs::remove_file(&path).unwrap();

        assert_eq!(single_response(&output), answer);
        assert_eq!(*stub.seen.lock().unwrap(), [PhishingRequest::Status]);
    }

    #[tokio::test]
    async fn refused_requests_get_one_error_and_never_connect() {
        let (path, listener) = silent_socket("refused");
        let claimed = MAX_REQUEST_BYTES + 1;
        let cases = [
            (
                frame(br#"{"SetMode":{"mode":"off"}}"#),
                "request not allowed",
            ),
            (frame(br#"{"Stats":{"uid":0}}"#), "request not allowed"),
            (frame(b"not json"), "malformed request"),
            (frame(br#""Status""#), "malformed request"),
            ((claimed as u32).to_ne_bytes().to_vec(), "request too large"),
        ];
        for (input, error) in cases {
            LARGEST.with(|largest| largest.set(0));
            let output = run(&input, &path).await;
            assert!(LARGEST.with(Cell::get) < claimed, "{error}");
            assert_eq!(
                single_response(&output),
                PhishingResponse::Error(error.into())
            );
        }
        let accepted = listener.accept();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(accepted.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    async fn missing_daemon_is_unreachable_well_inside_the_deadline() {
        let started = std::time::Instant::now();
        let output = run(&frame(br#"{"Status":null}"#), &socket_path("absent")).await;

        assert!(started.elapsed() < DEADLINE / 5);
        assert_eq!(output, frame(br#"{"Error":"daemon unreachable"}"#));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_daemon_is_unreachable_at_the_deadline() {
        let (path, listener) = silent_socket("silent");
        let started = Instant::now();
        let output = run(&frame(br#"{"Status":null}"#), &path).await;
        let accepted = listener.accept();
        std::fs::remove_file(&path).unwrap();

        assert!(accepted.is_ok(), "the host connected and waited");
        assert!((DEADLINE..DEADLINE + Duration::from_secs(1)).contains(&started.elapsed()));
        assert_eq!(
            single_response(&output),
            PhishingResponse::Error(UNREACHABLE.into())
        );
    }

    #[tokio::test]
    async fn daemon_answer_over_chromes_limit_becomes_an_error() {
        let huge = PhishingResponse::Error("a".repeat(MAX_RESPONSE_BYTES));
        let (path, _stub) = stub_daemon("huge", huge).await;
        let output = run(&frame(br#"{"Status":null}"#), &path).await;
        std::fs::remove_file(&path).unwrap();

        assert_eq!(
            single_response(&output),
            PhishingResponse::Error("daemon answer too large".into())
        );
    }

    #[tokio::test]
    async fn errors_never_quote_the_input() {
        let inputs: [&[u8]; 4] = [
            br#"{"CheckMail":{"to":"riggs-marker"}}"#,
            br#"{"riggs-marker":null}"#,
            br#"{"Trust":{"uid":0,"domain":"riggs-marker"}}"#,
            b"riggs-marker",
        ];
        for input in inputs {
            let output = run(&frame(input), &socket_path("never-used")).await;
            assert!(matches!(
                single_response(&output),
                PhishingResponse::Error(_)
            ));
            assert!(!String::from_utf8_lossy(&output).contains("riggs-marker"));
        }
    }
}
