//! `run`: the loopback HTTPS endpoint. It serves the task pane's files and forwards one kind of
//! request, a mail observation, to the daemon, which keys it by this process's uid. Anything
//! that can make it send a request acts as this user towards the daemon, so the token, `Host`
//! and `Origin` checks are what keep other local users and web pages out.
//!
//! Nothing from a request is logged: log lines are fixed strings plus a status code.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use riggs_comms::{ClientMessage, DaemonMessage, IpcClient};
use riggs_types::phishing::{MailObservation, PhishingRequest, PhishingResponse, Provider};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::setup::{is_token, time_left};

const ASSETS: [(&str, &str); 7] = [
    ("taskpane.html", "text/html; charset=utf-8"),
    ("taskpane.js", "text/javascript; charset=utf-8"),
    ("icon-16.png", "image/png"),
    ("icon-32.png", "image/png"),
    ("icon-64.png", "image/png"),
    ("icon-80.png", "image/png"),
    ("icon-128.png", "image/png"),
];
const MAX_BODY: usize = 8 * 1024 * 1024;
const DAEMON_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// A WebKit view opens about 6 connections to one host (NSURLSession's documented default, in
/// the macOS SDK's NSURLSession.h). A launchd job's soft limit is 256 descriptors
/// (`launchctl limit maxfiles`). Each connection takes one, an observation a second for the
/// daemon socket, and the process about 20 more: 2 * 64 + 20 stays under 256.
const MAX_CONNECTIONS: usize = 64;
/// How long a connection may wait for a request's headers, first or next.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest a connection lives, whatever it is doing. The add-in reconnects.
const LIFETIME: Duration = Duration::from_secs(60);
/// What a request in flight at the lifetime gets to finish: the daemon's 5 s, the rest of a body
/// from a slow local client, and writing the answer, with room to spare.
const GRACE: Duration = Duration::from_secs(15);

// The daemon's limits, `MailObservation::check_limits` in riggs-types; the tests hold these to it.
const MAX_STRING: usize = 4 * 1024;
const MAX_HREF: usize = 8 * 1024;
const MAX_BODY_TEXT: usize = 64 * 1024;
const MAX_RECIPIENTS: usize = 500;
const MAX_LINKS: usize = 500;
const MAX_ATTACHMENTS: usize = 100;
/// docs/PHISHING.md, "Capping", step 2: the serialized observation stays well under the
/// daemon's 8 MiB frame, so a mail cannot escape the check by being too large to deliver.
const MAX_REQUEST: usize = 6 * 1024 * 1024;
/// riggs-phish-padding.md: no prose has a longer run of these characters; base64 filler does.
/// The characters are ASCII, so a run's length in bytes is its length in characters.
const MAX_PADDING_RUN: usize = 256;

/// A 200 answer's content type and body, or the error status.
type Answer = Result<(&'static str, Bytes), StatusCode>;

pub struct Bridge {
    pub port: u16,
    token: String,
    hosts: [String; 2],
    origins: [String; 2],
    socket: PathBuf,
    files: HashMap<&'static str, (&'static str, Bytes)>,
    max_connections: usize,
    idle_timeout: Duration,
    lifetime: Duration,
    grace: Duration,
}

/// Reads the state written by `setup` and the assets; fails on anything missing or expired.
pub fn load(dir: &Path, assets: &Path, socket: PathBuf) -> anyhow::Result<(Bridge, TlsAcceptor)> {
    let state = |name: &str| {
        let path = dir.join(name);
        fs::read_to_string(&path).with_context(|| {
            format!(
                "cannot read {}; run `riggs-mailbridge setup` first",
                path.display()
            )
        })
    };
    let token = state("token")?;
    if !is_token(&token) {
        bail!("the state's token is malformed; run `riggs-mailbridge setup --renew`");
    }
    let port: u16 = state("port")?
        .parse()
        .context("the state's port file is malformed; run `riggs-mailbridge setup`")?;
    let cert = dir.join("cert.pem");
    if time_left(&cert)?.is_none() {
        bail!(
            "{} has expired or is not valid yet; run `riggs-mailbridge setup --renew` and trust the new certificate",
            cert.display()
        );
    }
    let chain = CertificateDer::pem_file_iter(&cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(dir.join("key.pem"))
        .with_context(|| format!("cannot read the key in {}", dir.display()))?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let files = ASSETS
        .iter()
        .map(|&(name, content_type)| {
            let path = assets.join(name);
            let bytes =
                fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            Ok((name, (content_type, Bytes::from(bytes))))
        })
        .collect::<anyhow::Result<_>>()?;
    let bridge = Bridge {
        port,
        token,
        hosts: [format!("localhost:{port}"), format!("127.0.0.1:{port}")],
        origins: [
            format!("https://localhost:{port}"),
            format!("https://127.0.0.1:{port}"),
        ],
        socket,
        files,
        max_connections: MAX_CONNECTIONS,
        idle_timeout: IDLE_TIMEOUT,
        lifetime: LIFETIME,
        grace: GRACE,
    };
    Ok((bridge, TlsAcceptor::from(Arc::new(tls))))
}

pub async fn bind(port: u16) -> anyhow::Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("cannot listen on 127.0.0.1:{port}"))?;
    info!("listening on 127.0.0.1:{}", listener.local_addr()?.port());
    Ok(listener)
}

pub async fn serve(
    listener: TcpListener,
    tls: TlsAcceptor,
    bridge: Arc<Bridge>,
) -> anyhow::Result<()> {
    let permits = Arc::new(Semaphore::new(bridge.max_connections));
    loop {
        // The permit comes first: past the cap, connections wait in the kernel's backlog.
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(_) => {
                warn!("accepting a connection failed");
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
        };
        let (tls, bridge) = (tls.clone(), Arc::clone(&bridge));
        let (idle_timeout, lifetime, grace) = (bridge.idle_timeout, bridge.lifetime, bridge.grace);
        tokio::spawn(async move {
            let _permit = permit;
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    // The alert names the client's reason, such as UnknownCA when it does not
                    // trust the certificate; it is one of a fixed set.
                    let alert = match error.get_ref().and_then(|e| e.downcast_ref()) {
                        Some(rustls::Error::AlertReceived(alert)) => format!("{alert:?}"),
                        _ => "none".into(),
                    };
                    warn!("TLS handshake failed, client alert: {alert}");
                    return;
                }
                Err(_) => {
                    warn!("TLS handshake timed out");
                    return;
                }
            };
            let service = service_fn(move |request| {
                let bridge = Arc::clone(&bridge);
                async move { Ok::<_, Infallible>(bridge.answer(request).await) }
            });
            // hyper's header read timeout also covers the wait for the next request, but not
            // a body that never arrives or a peer that never reads the answer: the lifetime does.
            // At the lifetime the connection finishes the request in flight, if any, and closes;
            // only a request still unfinished after the grace period is cut.
            let mut connection = std::pin::pin!(http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(idle_timeout)
                .serve_connection(TokioIo::new(stream), service));
            let ended = match tokio::time::timeout(lifetime, connection.as_mut()).await {
                Ok(ended) => ended,
                Err(_) => {
                    connection.as_mut().graceful_shutdown();
                    match tokio::time::timeout(grace, connection).await {
                        Ok(ended) => ended,
                        Err(_) => return warn!("HTTP connection cut after its grace period"),
                    }
                }
            };
            if ended.is_err() {
                warn!("HTTP connection ended with an error");
            }
        });
    }
}

impl Bridge {
    async fn answer(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let (status, content_type, body) = match self.route(request).await {
            Ok((content_type, body)) => (StatusCode::OK, Some(content_type), body),
            Err(status) => (status, None, Bytes::new()),
        };
        info!("answered {}", status.as_u16());
        let mut response = Response::new(Full::new(body));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        // Keeps the token out of cross-origin referrers. Not no-referrer: under it a POST whose
        // mode is not "cors" carries `Origin: null` (Fetch, "append a request `Origin` header").
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        );
        if let Some(content_type) = content_type {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        response
    }

    async fn route(&self, request: Request<Incoming>) -> Answer {
        if !only_value_is(&request, header::HOST, &self.hosts) {
            return Err(StatusCode::FORBIDDEN);
        }
        let name = request
            .uri()
            .path()
            .strip_prefix('/')
            .and_then(|path| path.split_once('/'))
            .filter(|(token, _)| bool::from(token.as_bytes().ct_eq(self.token.as_bytes())))
            .map(|(_, name)| name);
        let file = name.and_then(|name| self.files.get(name)).cloned();
        let observe = name == Some("observe");
        let known = file.is_some() || observe;
        match (request.method().clone(), file) {
            (Method::GET | Method::HEAD, Some(file)) => Ok(file),
            (Method::POST, None) if observe => self.observe(request).await,
            _ if known => Err(StatusCode::METHOD_NOT_ALLOWED),
            _ => Err(StatusCode::NOT_FOUND),
        }
    }

    async fn observe(&self, request: Request<Incoming>) -> Answer {
        if !only_value_is(&request, header::ORIGIN, &self.origins) {
            return Err(StatusCode::FORBIDDEN);
        }
        let json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        let body = request.into_body();
        if body.size_hint().lower() > MAX_BODY as u64 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let body = Limited::new(body, MAX_BODY)
            .collect()
            .await
            .map_err(|error| {
                if error.is::<LengthLimitError>() {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                }
            })?
            .to_bytes();
        let mut value: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        value
            .as_object_mut()
            .ok_or(StatusCode::BAD_REQUEST)?
            .insert("provider".into(), serde_json::json!(Provider::OutlookAddin));
        let mail: MailObservation =
            serde_json::from_value(value).map_err(|_| StatusCode::BAD_REQUEST)?;

        let request = ClientMessage::Phishing(PhishingRequest::CheckMail(Box::new(cap(mail))));
        let answer = tokio::time::timeout(DAEMON_TIMEOUT, async {
            IpcClient::connect(&self.socket).await?.send(&request).await
        })
        .await;
        match answer {
            Ok(Ok(DaemonMessage::Phishing(PhishingResponse::Verdict(verdict)))) => {
                let shown = Some(verdict).filter(|verdict| verdict.show);
                let body = serde_json::to_vec(&shown).expect("a verdict serializes");
                Ok(("application/json", Bytes::from(body)))
            }
            _ => {
                warn!("the daemon gave no verdict");
                Err(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }
}

fn only_value_is(request: &Request<Incoming>, name: HeaderName, allowed: &[String; 2]) -> bool {
    let mut values = request.headers().get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => allowed.iter().any(|a| value.as_bytes() == a.as_bytes()),
        _ => false,
    }
}

/// Makes an observation fit the daemon's limits as docs/PHISHING.md, "Capping", describes,
/// after first removing padding from the body (riggs-phish-padding.md): lists keep their first
/// entries, strings are cut on a character boundary, then links and then recipients are dropped
/// from the end until the request fits its budget. `truncated` stays set if the pane set it and
/// is set when anything was removed or cut.
fn cap(mut mail: MailObservation) -> MailObservation {
    let unpadded = remove_padding(&mut mail.body_text);
    let fields = [
        cut_list(&mut mail.to, MAX_RECIPIENTS),
        cut_list(&mut mail.links, MAX_LINKS),
        cut_list(&mut mail.attachments, MAX_ATTACHMENTS),
        cut(&mut mail.message_id, MAX_STRING),
        cut(&mut mail.from_name, MAX_STRING),
        cut(&mut mail.from_addr, MAX_STRING),
        mail.reply_to
            .as_mut()
            .is_some_and(|reply_to| cut(reply_to, MAX_STRING)),
        cut(&mut mail.subject, MAX_STRING),
        cut(&mut mail.body_text, MAX_BODY_TEXT),
    ];
    let items = mail
        .to
        .iter_mut()
        .chain(&mut mail.attachments)
        .map(|item| cut(item, MAX_STRING))
        .chain(mail.links.iter_mut().flat_map(|link| {
            [
                cut(&mut link.text, MAX_STRING),
                cut(&mut link.href, MAX_HREF),
            ]
        }))
        .fold(false, |any, cut| any | cut);
    let mut cut_anything = unpadded || fields.contains(&true) || items;

    let mut size = json_len(&mail);
    while size > MAX_REQUEST {
        // An entry and the comma before it, unless it was the only one.
        size -= match mail.links.pop() {
            Some(link) => json_len(&link) + usize::from(!mail.links.is_empty()),
            None => {
                // Without links or recipients a capped mail is under 3 MiB even fully escaped.
                let recipient = mail.to.pop().expect("recipients left to drop");
                json_len(&recipient) + usize::from(!mail.to.is_empty())
            }
        };
        cut_anything = true;
    }
    mail.truncated |= cut_anything;
    mail
}

/// Replaces each run of more than `MAX_PADDING_RUN` base64-like characters with one space:
/// phishing hides such filler before the visible text, where the body limit would keep only it.
fn remove_padding(text: &mut String) -> bool {
    let is_padding = |c: char| c.is_ascii_alphanumeric() || "+/=_-".contains(c);
    let mut kept = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find(is_padding) {
        let len = rest[start..]
            .find(|c| !is_padding(c))
            .unwrap_or(rest.len() - start);
        let run = &rest[start..start + len];
        kept.push_str(&rest[..start]);
        kept.push_str(if run.len() > MAX_PADDING_RUN {
            " "
        } else {
            run
        });
        rest = &rest[start + len..];
    }
    kept.push_str(rest);
    // A removed run always shortens the text, and nothing else changes it.
    let removed = kept.len() != text.len();
    *text = kept;
    removed
}

fn cut(text: &mut String, max: usize) -> bool {
    let over = text.len() > max;
    text.truncate(text.floor_char_boundary(max));
    over
}

fn cut_list<T>(list: &mut Vec<T>, max: usize) -> bool {
    let over = list.len() > max;
    list.truncate(max);
    over
}

fn json_len(value: &impl Serialize) -> usize {
    serde_json::to_vec(value)
        .expect("observations serialize")
        .len()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::IpAddr;
    use std::sync::Mutex;

    use riggs_comms::{DaemonState, IpcServer, PhishingQuery};
    use riggs_types::phishing::{Level, Link, PhishingVerdict, Reason};
    use rustls::pki_types::ServerName;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::setup::setup;

    pub(crate) fn write_assets(assets: &Path) {
        fs::create_dir_all(assets).unwrap();
        fs::write(
            assets.join("manifest.template.xml"),
            "<Url>https://localhost:{{PORT}}/{{TOKEN}}/taskpane.html</Url>",
        )
        .unwrap();
        for (name, _) in ASSETS {
            fs::write(assets.join(name), format!("stand-in {name}")).unwrap();
        }
    }

    enum Daemon {
        Answers(PhishingResponse),
        Silent,
        Absent,
    }

    struct Stub {
        answer: PhishingResponse,
        seen: Mutex<Vec<(u32, PhishingRequest)>>,
    }

    impl PhishingQuery for Stub {
        fn handle(&self, uid: u32, request: PhishingRequest) -> PhishingResponse {
            self.seen.lock().unwrap().push((uid, request));
            self.answer.clone()
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        port: u16,
        token: String,
        connector: TlsConnector,
        stub: Option<Arc<Stub>>,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Reply {
        fn header(&self, name: &str) -> Option<&str> {
            let mut values = self.headers.iter().filter(|(n, _)| n == name);
            let value = values.next().map(|(_, value)| value.as_str());
            assert!(values.next().is_none(), "{name} appears twice");
            value
        }

        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap()
        }

        /// Everything but `date`, which differs between any two answers.
        fn without_date(mut self) -> Self {
            self.headers.retain(|(name, _)| name != "date");
            self
        }
    }

    fn client_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    }

    async fn start(daemon: Daemon) -> Harness {
        start_with(daemon, |_| {}).await
    }

    async fn start_with(daemon: Daemon, tune: impl FnOnce(&mut Bridge)) -> Harness {
        captured_log();
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let assets = dir.path().join("assets");
        let socket = dir.path().join("riggs.sock");
        write_assets(&assets);
        let listener = bind(0).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        setup(&state, &assets, Some(port), false).unwrap();

        let stub = match daemon {
            Daemon::Answers(answer) => {
                let stub = Arc::new(Stub {
                    answer,
                    seen: Mutex::default(),
                });
                let daemon = Arc::new(DaemonState::new());
                *daemon.phishing.write().unwrap() =
                    Some(Arc::clone(&stub) as Arc<dyn PhishingQuery>);
                let server = IpcServer::with_state(socket.clone(), daemon);
                tokio::spawn(async move { server.start().await });
                while !socket.exists() {
                    tokio::task::yield_now().await;
                }
                Some(stub)
            }
            Daemon::Silent => {
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::spawn(async move {
                    let mut held = Vec::new();
                    loop {
                        held.push(listener.accept().await.unwrap().0);
                    }
                });
                None
            }
            Daemon::Absent => None,
        };

        let (mut bridge, tls) = load(&state, &assets, socket).unwrap();
        tune(&mut bridge);
        tokio::spawn(serve(listener, tls, Arc::new(bridge)));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(state.join("ca.pem")).unwrap())
            .unwrap();
        Harness {
            _dir: dir,
            port,
            token: fs::read_to_string(state.join("token")).unwrap(),
            connector: TlsConnector::from(client_config(roots)),
            stub,
        }
    }

    impl Harness {
        async fn connect(&self) -> tokio_rustls::client::TlsStream<TcpStream> {
            let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))
                .await
                .unwrap();
            let name = ServerName::try_from("localhost").unwrap();
            self.connector.connect(name, tcp).await.unwrap()
        }

        /// One request on its own connection, the answer as far as the server sent it.
        /// No answer at all, hyper's own included, may carry an `Access-Control-*` header.
        async fn send_unchecked(&self, request: &[u8], server_name: &'static str) -> Reply {
            let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))
                .await
                .unwrap();
            let name = ServerName::try_from(server_name).unwrap();
            let mut tls = self.connector.connect(name, tcp).await.unwrap();
            tls.write_all(request).await.unwrap();
            let mut raw = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut raw)).await;
            let end = raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("a complete answer head");
            let head = std::str::from_utf8(&raw[..end]).unwrap();
            let mut lines = head.split("\r\n");
            let status = lines
                .next()
                .unwrap()
                .split(' ')
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            let headers: Vec<_> = lines
                .map(|line| {
                    let (name, value) = line.split_once(':').unwrap();
                    (name.to_ascii_lowercase(), value.trim().to_string())
                })
                .collect();
            for (name, _) in &headers {
                assert!(!name.starts_with("access-control-"), "{name}");
            }
            Reply {
                status,
                headers,
                body: raw[end + 4..].to_vec(),
            }
        }

        /// As `send_unchecked`, for answers the bridge itself wrote.
        async fn send(&self, request: &[u8]) -> Reply {
            let reply = self.send_unchecked(request, "localhost").await;
            assert_eq!(reply.header("cache-control"), Some("no-store"));
            assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
            assert_eq!(reply.header("referrer-policy"), Some("same-origin"));
            reply
        }

        fn request(&self, method: &str, path: &str) -> Vec<u8> {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                self.port
            )
            .into_bytes()
        }

        fn post(&self, headers: &str, body: &[u8]) -> Vec<u8> {
            let mut request = format!(
                "POST /{}/observe HTTP/1.1\r\nHost: localhost:{}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                self.token,
                self.port,
                body.len()
            )
            .into_bytes();
            request.extend_from_slice(body);
            request
        }

        fn json_headers(&self) -> String {
            format!(
                "Origin: https://localhost:{}\r\nContent-Type: application/json\r\n",
                self.port
            )
        }

        async fn observe(&self, mail: &Value) -> Reply {
            let request = self.post(&self.json_headers(), mail.to_string().as_bytes());
            self.send(&request).await
        }

        fn seen(&self) -> Vec<(u32, PhishingRequest)> {
            self.stub.as_ref().unwrap().seen.lock().unwrap().clone()
        }
    }

    fn mail() -> Value {
        json!({
            "provider": "outlook_addin",
            "message_id": "m1",
            "from_name": "Sender",
            "from_addr": "sender@example.com",
            "reply_to": null,
            "to": ["user@example.com"],
            "subject": "Hello",
            "body_text": "Hi",
            "links": [{"text": "here", "href": "https://example.com/"}],
            "attachments": [],
            "truncated": false,
        })
    }

    fn verdict(show: bool) -> PhishingVerdict {
        PhishingVerdict {
            level: Level::Caution,
            reasons: vec![Reason {
                cue: "example_cue".into(),
                text: "example reason".into(),
            }],
            show,
        }
    }

    async fn shown() -> Harness {
        start(Daemon::Answers(PhishingResponse::Verdict(verdict(true)))).await
    }

    #[tokio::test]
    async fn serves_each_asset_with_its_content_type_by_get_and_head() {
        let harness = shown().await;
        for (name, content_type) in ASSETS {
            let path = format!("/{}/{name}", harness.token);
            let get = harness.send(&harness.request("GET", &path)).await;
            assert_eq!(get.status, 200, "{name}");
            assert_eq!(get.header("content-type"), Some(content_type));
            assert_eq!(get.body, format!("stand-in {name}").as_bytes());

            let head = harness.send(&harness.request("HEAD", &path)).await;
            assert_eq!(head.status, 200, "{name}");
            assert_eq!(head.header("content-length"), get.header("content-length"));
            assert!(head.body.is_empty());

            // Office appends `_host_info` to add-in page URLs; only the path is matched.
            let queried = format!("{path}?_host_info=x");
            let reply = harness.send(&harness.request("GET", &queried)).await;
            assert_eq!(reply.without_date(), get.clone().without_date(), "{name}");
            let reply = harness.send(&harness.request("HEAD", &queried)).await;
            assert_eq!(reply.without_date(), head.clone().without_date(), "{name}");
        }

        let page = format!("/{}/taskpane.html", harness.token);
        let by_ip = format!(
            "GET {page} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            harness.port
        );
        let reply = harness.send_unchecked(by_ip.as_bytes(), "127.0.0.1").await;
        assert_eq!(reply.status, 200);
    }

    #[tokio::test]
    async fn a_wrong_token_and_an_unknown_path_get_the_same_404() {
        let harness = shown().await;
        let token = &harness.token;
        let mut wrong = token.clone().into_bytes();
        wrong[7] = if wrong[7] == b'0' { b'1' } else { b'0' };
        let wrong = String::from_utf8(wrong).unwrap();
        let paths = [
            format!("/{wrong}/taskpane.html"),
            format!("/{}/taskpane.html", &token[..31]),
            format!("/{token}0/taskpane.html"),
            format!("/{}/taskpane.html", token.to_uppercase()),
            "//taskpane.html".to_string(),
            "/taskpane.html".to_string(),
            "/".to_string(),
            format!("/{token}"),
            format!("/{token}/"),
            format!("/{token}/taskpane.html/"),
            format!("/{token}/../{token}/taskpane.html"),
            format!("/x/../{token}/taskpane.html"),
            format!("/{token}/..%2Ftaskpane.html"),
            format!("/{token}%2Ftaskpane.html"),
            format!("/{token}/%74askpane.html"),
            format!("/{token}/manifest.xml"),
            format!("/{token}/manifest.template.xml"),
            format!("/{token}/token"),
            format!("/{token}/key.pem"),
        ];
        let first = harness
            .send(&harness.request("GET", &paths[0]))
            .await
            .without_date();
        assert_eq!(first.status, 404);
        for path in &paths[1..] {
            let reply = harness.send(&harness.request("GET", path)).await;
            assert_eq!(reply.without_date(), first, "{path}");
        }
        let body = mail().to_string();
        for path in [format!("/{wrong}/observe"), format!("/{token}/observe/")] {
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: localhost:{}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                harness.port,
                harness.json_headers(),
                body.len()
            );
            let reply = harness.send(request.as_bytes()).await;
            assert_eq!(reply.without_date(), first, "POST {path}");
        }
        assert!(harness.seen().is_empty());
    }

    #[tokio::test]
    async fn a_request_target_hyper_cannot_parse_is_refused_without_cors_headers() {
        let harness = shown().await;
        let request = format!(
            "GET {}/taskpane.html HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            harness.token, harness.port
        );
        let reply = harness
            .send_unchecked(request.as_bytes(), "localhost")
            .await;
        assert_eq!(reply.status, 400);
    }

    #[tokio::test]
    async fn host_must_be_localhost_or_127_0_0_1_with_the_port() {
        let harness = shown().await;
        let (port, token) = (harness.port, &harness.token);
        let hosts = [
            format!("Host: example.com:{port}\r\n"),
            "Host: localhost\r\n".to_string(),
            format!("Host: localhost:{}\r\n", port.wrapping_add(1)),
            format!("Host: [::1]:{port}\r\n"),
            format!("Host: localhost:{port}\r\nHost: localhost:{port}\r\n"),
            String::new(),
        ];
        for host in hosts {
            let get =
                format!("GET /{token}/taskpane.html HTTP/1.1\r\n{host}Connection: close\r\n\r\n");
            assert_eq!(harness.send(get.as_bytes()).await.status, 403, "{host}");
            let body = mail().to_string();
            let post = format!(
                "POST /{token}/observe HTTP/1.1\r\n{host}{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                harness.json_headers(),
                body.len()
            );
            assert_eq!(harness.send(post.as_bytes()).await.status, 403, "{host}");
        }
        assert!(harness.seen().is_empty());
    }

    #[tokio::test]
    async fn a_post_needs_the_bridges_own_origin() {
        let harness = shown().await;
        let port = harness.port;
        let body = mail().to_string();
        let origins = [
            String::new(),
            "Origin: null\r\n".to_string(),
            "Origin: https://example.com\r\n".to_string(),
            format!("Origin: http://localhost:{port}\r\n"),
            format!("Origin: https://localhost:{}\r\n", port.wrapping_add(1)),
            "Origin: https://localhost\r\n".to_string(),
            format!("Origin: https://localhost:{port}\r\nOrigin: https://localhost:{port}\r\n"),
        ];
        for origin in origins {
            let headers = format!("{origin}Content-Type: application/json\r\n");
            let reply = harness.send(&harness.post(&headers, body.as_bytes())).await;
            assert_eq!(reply.status, 403, "{origin}");
        }
        assert!(harness.seen().is_empty());

        let headers =
            format!("Origin: https://127.0.0.1:{port}\r\nContent-Type: application/json\r\n");
        let reply = harness.send(&harness.post(&headers, body.as_bytes())).await;
        assert_eq!(reply.status, 200);
    }

    #[tokio::test]
    async fn a_post_needs_json() {
        let harness = shown().await;
        let origin = format!("Origin: https://localhost:{}\r\n", harness.port);
        let body = mail().to_string();
        for content_type in [
            "",
            "Content-Type: text/plain\r\n",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "Content-Type: multipart/form-data; boundary=x\r\n",
            "Content-Type: application/jsonx\r\n",
        ] {
            let headers = format!("{origin}{content_type}");
            let reply = harness.send(&harness.post(&headers, body.as_bytes())).await;
            assert_eq!(reply.status, 415, "{content_type}");
        }
        assert!(harness.seen().is_empty());

        let headers = format!("{origin}Content-Type: application/json; charset=utf-8\r\n");
        let reply = harness.send(&harness.post(&headers, body.as_bytes())).await;
        assert_eq!(reply.status, 200);
    }

    #[tokio::test]
    async fn a_body_over_8_mib_is_refused_before_it_is_sent() {
        let harness = shown().await;
        // Only the head is sent: an answer proves the server did not wait for the body.
        let head = format!(
            "POST /{}/observe HTTP/1.1\r\nHost: localhost:{}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            harness.token,
            harness.port,
            harness.json_headers(),
            MAX_BODY + 1
        );
        let reply = harness.send(head.as_bytes()).await;
        assert_eq!(reply.status, 413);
        assert!(harness.seen().is_empty());
    }

    #[tokio::test]
    async fn malformed_json_or_a_body_that_is_not_an_observation_is_400() {
        let harness = shown().await;
        let mut wrong_type = mail();
        wrong_type["to"] = json!("user@example.com");
        let mut missing = mail();
        missing.as_object_mut().unwrap().remove("from_addr");
        let bodies = [
            "{".to_string(),
            "".to_string(),
            "[]".to_string(),
            "null".to_string(),
            "\"text\"".to_string(),
            wrong_type.to_string(),
            missing.to_string(),
            // An unpaired surrogate escape: serde_json refuses it in a string.
            mail().to_string().replace("Hello", r"\ud83d"),
        ];
        for body in bodies {
            let reply = harness
                .send(&harness.post(&harness.json_headers(), body.as_bytes()))
                .await;
            assert_eq!(reply.status, 400, "{body}");
        }
        assert!(harness.seen().is_empty());
    }

    #[tokio::test]
    async fn other_methods_get_405_and_never_a_cors_answer() {
        let harness = shown().await;
        let token = &harness.token;
        let preflight = |path: &str| {
            format!(
                "OPTIONS {path} HTTP/1.1\r\nHost: localhost:{}\r\nOrigin: https://example.com\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\nConnection: close\r\n\r\n",
                harness.port
            )
        };
        for path in [
            format!("/{token}/observe"),
            format!("/{token}/taskpane.html"),
        ] {
            let reply = harness.send(preflight(&path).as_bytes()).await;
            assert_eq!(reply.status, 405, "{path}");
        }
        let cases = [
            ("PUT", "taskpane.html"),
            ("DELETE", "taskpane.html"),
            ("PATCH", "icon-16.png"),
            ("POST", "taskpane.html"),
            ("GET", "observe"),
            ("HEAD", "observe"),
            ("OPTIONS", "observe"),
            ("TRACE", "taskpane.html"),
        ];
        for (method, name) in cases {
            let reply = harness
                .send(&harness.request(method, &format!("/{token}/{name}")))
                .await;
            assert_eq!(reply.status, 405, "{method} {name}");
        }
        // A wrong token answers 404 whatever the method, so no method tells a token apart.
        let reply = harness.send(preflight("/0/observe").as_bytes()).await;
        assert_eq!(reply.status, 404);
        assert!(harness.seen().is_empty());
    }

    #[tokio::test]
    async fn the_observation_reaches_the_daemon_capped_with_this_users_uid() {
        let harness = shown().await;
        let mut long = mail();
        long["provider"] = json!("gmail");
        // 4097 bytes: the cut at 4096 would split the last two-byte character.
        long["subject"] = json!(format!("a{}", "é".repeat(2048)));
        long["to"] = json!(vec!["user@example.com"; MAX_RECIPIENTS + 1]);
        assert_eq!(harness.observe(&long).await.status, 200);

        let mut provider_missing = mail();
        provider_missing.as_object_mut().unwrap().remove("provider");
        assert_eq!(harness.observe(&provider_missing).await.status, 200);
        let mut said_so = mail();
        said_so["truncated"] = json!(true);
        assert_eq!(harness.observe(&said_so).await.status, 200);
        // The pane sends bodies of up to a million characters uncut, padding included.
        let mut padded = mail();
        padded["body_text"] = json!(format!("{} Hi", run(1_000_000)));
        assert_eq!(harness.observe(&padded).await.status, 200);

        let seen = harness.seen();
        assert_eq!(seen.len(), 4);
        let uid = unsafe { libc::geteuid() };
        let mails: Vec<MailObservation> = seen
            .into_iter()
            .map(|(seen_uid, request)| {
                assert_eq!(seen_uid, uid);
                match request {
                    PhishingRequest::CheckMail(mail) => *mail,
                    other => panic!("{other:?}"),
                }
            })
            .collect();
        for mail in &mails {
            assert_eq!(mail.provider, Provider::OutlookAddin);
            assert_eq!(mail.check_limits(), Ok(()));
        }
        assert_eq!(mails[0].subject, format!("a{}", "é".repeat(2047)));
        assert_eq!(mails[0].subject.len(), 4095);
        assert_eq!(mails[0].to.len(), MAX_RECIPIENTS);
        assert!(mails[0].truncated);
        let untouched: MailObservation = serde_json::from_value(mail()).unwrap();
        assert_eq!(mails[1], untouched);
        assert!(!mails[1].truncated);
        assert!(mails[2].truncated);
        assert_eq!(mails[3].body_text, "  Hi");
        assert!(mails[3].truncated);
    }

    #[tokio::test]
    async fn a_shown_verdict_comes_back_unchanged_and_a_hidden_one_as_null() {
        let harness = shown().await;
        let reply = harness.observe(&mail()).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-type"), Some("application/json"));
        assert_eq!(reply.json(), serde_json::to_value(verdict(true)).unwrap());

        // A query on the POST is ignored like one on a file.
        let request = harness.post(&harness.json_headers(), mail().to_string().as_bytes());
        let request =
            String::from_utf8(request)
                .unwrap()
                .replacen("/observe ", "/observe?_host_info=x ", 1);
        let queried = harness.send(request.as_bytes()).await;
        assert_eq!(queried.without_date(), reply.without_date());
        assert_eq!(harness.seen().len(), 2);

        let harness = start(Daemon::Answers(PhishingResponse::Verdict(verdict(false)))).await;
        let reply = harness.observe(&mail()).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"null");
    }

    #[tokio::test]
    async fn no_verdict_from_the_daemon_is_503() {
        let not_verdicts = [
            PhishingResponse::Ok,
            PhishingResponse::Error("phishing protection not running".into()),
        ];
        for answer in not_verdicts {
            let harness = start(Daemon::Answers(answer)).await;
            assert_eq!(harness.observe(&mail()).await.status, 503);
            assert_eq!(harness.seen().len(), 1);
        }
        let harness = start(Daemon::Absent).await;
        assert_eq!(harness.observe(&mail()).await.status, 503);

        let harness = start(Daemon::Silent).await;
        let started = std::time::Instant::now();
        assert_eq!(harness.observe(&mail()).await.status, 503);
        assert!(started.elapsed() >= DAEMON_TIMEOUT);
    }

    /// True if the server ended the connection within a few seconds, whatever it was sent.
    async fn is_closed_soon(stream: &mut (impl AsyncReadExt + Unpin)) -> bool {
        let mut sink = Vec::new();
        let read = stream.read_to_end(&mut sink);
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn at_the_cap_one_more_connection_waits_until_one_ends() {
        let harness = start_with(
            Daemon::Answers(PhishingResponse::Verdict(verdict(true))),
            |bridge| bridge.max_connections = 2,
        )
        .await;
        let (first, _second) = (harness.connect().await, harness.connect().await);

        let page = harness.request("GET", &format!("/{}/taskpane.html", harness.token));
        let mut third = std::pin::pin!(harness.send(&page));
        let waited = tokio::time::timeout(Duration::from_millis(500), &mut third).await;
        assert!(waited.is_err(), "served beyond the cap");

        drop(first);
        let reply = tokio::time::timeout(Duration::from_secs(5), third)
            .await
            .expect("served once a connection ended");
        assert_eq!(reply.status, 200);
    }

    #[tokio::test]
    async fn a_connection_idle_before_or_between_requests_is_closed() {
        let harness = start_with(
            Daemon::Answers(PhishingResponse::Verdict(verdict(true))),
            |bridge| bridge.idle_timeout = Duration::from_millis(300),
        )
        .await;
        let mut silent = harness.connect().await;
        assert!(is_closed_soon(&mut silent).await);

        let mut kept = harness.connect().await;
        let page = format!(
            "GET /{}/taskpane.html HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            harness.token, harness.port
        );
        kept.write_all(page.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        while !answer.ends_with(b"stand-in taskpane.html") {
            let mut chunk = [0; 1024];
            let read = kept.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "closed before the answer");
            answer.extend_from_slice(&chunk[..read]);
        }
        assert!(is_closed_soon(&mut kept).await);
    }

    #[tokio::test]
    async fn a_connection_is_closed_at_its_lifetime_even_if_a_body_never_arrives() {
        let harness = start_with(
            Daemon::Answers(PhishingResponse::Verdict(verdict(true))),
            |bridge| {
                bridge.lifetime = Duration::from_millis(300);
                bridge.grace = Duration::from_millis(300);
            },
        )
        .await;
        let mut stalled = harness.connect().await;
        let head = format!(
            "POST /{}/observe HTTP/1.1\r\nHost: localhost:{}\r\n{}Content-Length: 100\r\n\r\n",
            harness.token,
            harness.port,
            harness.json_headers()
        );
        stalled.write_all(head.as_bytes()).await.unwrap();
        assert!(is_closed_soon(&mut stalled).await);
        assert!(harness.seen().is_empty());
    }

    #[tokio::test]
    async fn a_request_in_flight_at_the_lifetime_is_answered() {
        let harness = start_with(
            Daemon::Answers(PhishingResponse::Verdict(verdict(true))),
            |bridge| bridge.lifetime = Duration::from_millis(300),
        )
        .await;
        let request = harness.post(&harness.json_headers(), mail().to_string().as_bytes());
        let (first, rest) = request.split_at(request.len() - 20);
        let mut stream = harness.connect().await;
        stream.write_all(first).await.unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        stream.write_all(rest).await.unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 200"));
        assert_eq!(harness.seen().len(), 1);
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed_at_once_at_the_lifetime() {
        // The idle timeout and the grace period are long: only the lifetime can end it quickly.
        let harness = start_with(
            Daemon::Answers(PhishingResponse::Verdict(verdict(true))),
            |bridge| {
                bridge.lifetime = Duration::from_millis(300);
                bridge.grace = Duration::from_secs(30);
            },
        )
        .await;
        let mut idle = harness.connect().await;
        assert!(is_closed_soon(&mut idle).await);
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// Everything every test logs, bridge and stub daemon alike. Global, because tracing caches
    /// a callsite's interest process-wide when it is first hit, possibly on another test's thread;
    /// every test that logs installs it before its first event.
    fn captured_log() -> &'static Captured {
        static LOG: std::sync::OnceLock<Captured> = std::sync::OnceLock::new();
        LOG.get_or_init(|| {
            let captured = Captured::default();
            let writer = captured.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            captured
        })
    }

    #[tokio::test]
    async fn nothing_from_a_request_reaches_the_log() {
        let captured = captured_log();
        let harness = shown().await;
        let marker = "marker-5d1c9e";
        let mut marked = mail();
        marked["subject"] = json!(marker);
        let marked = marked.to_string();
        let origin = format!("Origin: https://localhost:{}\r\n", harness.port);
        let requests = [
            (
                format!("{origin}Content-Type: text/plain\r\n"),
                marked.clone(),
                415,
            ),
            (
                format!("Origin: https://{marker}.example\r\nContent-Type: application/json\r\n"),
                marked.clone(),
                403,
            ),
            (harness.json_headers(), format!("{{\"{marker}\": "), 400),
            (harness.json_headers(), marked.clone(), 200),
        ];
        for (headers, body, status) in requests {
            let reply = harness.send(&harness.post(&headers, body.as_bytes())).await;
            assert_eq!(reply.status, status);
        }
        let path = format!("/{marker}/taskpane.html");
        assert_eq!(
            harness.send(&harness.request("GET", &path)).await.status,
            404
        );
        let query = format!("/{}/taskpane.html?_host_info={marker}", harness.token);
        assert_eq!(
            harness.send(&harness.request("GET", &query)).await.status,
            200
        );

        let untrusting = TlsConnector::from(client_config(rustls::RootCertStore::empty()));
        let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, harness.port))
            .await
            .unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        assert!(untrusting.connect(name, tcp).await.is_err());
        for _ in 0..100 {
            if captured.text().contains("client alert") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let log = captured.text();
        for line in [
            "answered 415",
            "answered 403",
            "answered 400",
            "answered 200",
            "answered 404",
            "TLS handshake failed, client alert: UnknownCA",
        ] {
            assert!(log.contains(line), "{line} missing from:\n{log}");
        }
        assert!(!log.contains(marker), "{log}");
        assert!(!log.contains(&harness.token), "{log}");
    }

    #[tokio::test]
    async fn it_binds_loopback_only_and_a_taken_port_is_an_error() {
        captured_log();
        let listener = bind(0).await.unwrap();
        let address = listener.local_addr().unwrap();
        assert_eq!(address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let error = bind(address.port()).await.unwrap_err();
        assert!(format!("{error:#}").contains("already in use"), "{error:#}");
    }

    #[test]
    fn load_fails_fast_on_missing_state_a_missing_asset_or_an_expired_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (state, assets) = (dir.path().join("state"), dir.path().join("assets"));
        write_assets(&assets);
        let error = |state: &Path| match load(state, &assets, PathBuf::new()) {
            Ok(_) => panic!("load succeeded"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error(&state).contains("run `riggs-mailbridge setup` first"));

        setup(&state, &assets, None, false).unwrap();
        assert!(load(&state, &assets, PathBuf::new()).is_ok());
        fs::remove_file(assets.join("icon-80.png")).unwrap();
        assert!(error(&state).contains("icon-80.png"));
        write_assets(&assets);

        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(10);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        fs::write(
            state.join("cert.pem"),
            params.self_signed(&key).unwrap().pem(),
        )
        .unwrap();
        assert!(error(&state).contains("has expired"));
    }

    fn at_limits() -> MailObservation {
        MailObservation {
            provider: Provider::OutlookAddin,
            message_id: "a".repeat(MAX_STRING),
            from_name: "a".repeat(MAX_STRING),
            from_addr: "a".repeat(MAX_STRING),
            reply_to: Some("a".repeat(MAX_STRING)),
            to: vec!["a".repeat(MAX_STRING)],
            subject: "a".repeat(MAX_STRING),
            // Prose-like: one long run of `a` would be removed as padding.
            body_text: "a ".repeat(MAX_BODY_TEXT / 2),
            links: vec![Link {
                text: "a".repeat(MAX_STRING),
                href: "a".repeat(MAX_HREF),
            }],
            attachments: vec!["a".repeat(MAX_STRING)],
            truncated: false,
        }
    }

    /// Each grows one string or list of `at_limits()` past the daemon's limit.
    const GROW: [fn(&mut MailObservation); 13] = [
        |m| m.message_id.push('b'),
        |m| m.from_name.push('b'),
        |m| m.from_addr.push('b'),
        |m| m.reply_to.as_mut().unwrap().push('b'),
        |m| m.subject.push('b'),
        |m| m.body_text.push('b'),
        |m| m.to[0].push('b'),
        |m| m.links[0].text.push('b'),
        |m| m.links[0].href.push('b'),
        |m| m.attachments[0].push('b'),
        |m| m.to.resize(MAX_RECIPIENTS + 1, String::new()),
        |m| m.links.resize(MAX_LINKS + 1, m.links[0].clone()),
        |m| m.attachments.resize(MAX_ATTACHMENTS + 1, String::new()),
    ];

    #[test]
    fn the_caps_are_exactly_the_daemons_limits() {
        assert_eq!(cap(at_limits()), at_limits());
        assert_eq!(at_limits().check_limits(), Ok(()));
        for (index, grow) in GROW.iter().enumerate() {
            let mut over = at_limits();
            grow(&mut over);
            assert!(over.check_limits().is_err(), "{index}");
            let capped = cap(over);
            assert!(capped.truncated, "{index}");
            assert_eq!(capped.check_limits(), Ok(()), "{index}");
            // Exactly at the limit: growing it again goes over.
            let mut again = capped.clone();
            grow(&mut again);
            assert!(
                again.check_limits().is_err(),
                "{index} was cut below the limit"
            );
        }
    }

    #[test]
    fn truncated_is_set_exactly_when_something_was_cut_or_the_pane_said_so() {
        for (pane, grow, expected) in [
            (false, None, false),
            (true, None, true),
            (false, Some(GROW[4]), true),
            (true, Some(GROW[4]), true),
        ] {
            let mut mail = at_limits();
            mail.truncated = pane;
            if let Some(grow) = grow {
                grow(&mut mail);
            }
            assert_eq!(cap(mail).truncated, expected);
        }
    }

    #[test]
    fn strings_are_cut_on_a_character_boundary() {
        let mut mail = at_limits();
        let prefix = format!("{}a", "a ".repeat((MAX_BODY_TEXT - 2) / 2));
        mail.body_text = format!("{prefix}€");
        mail.links[0].href = format!("{}😀", "a".repeat(MAX_HREF - 2));
        let capped = cap(mail);
        assert_eq!(capped.body_text, prefix);
        assert_eq!(prefix.len(), MAX_BODY_TEXT - 1);
        assert_eq!(capped.links[0].href, "a".repeat(MAX_HREF - 2));
        assert!(capped.truncated);
    }

    #[test]
    fn an_oversized_request_drops_links_then_recipients_from_the_end() {
        let mut mail = at_limits();
        mail.links = vec![mail.links[0].clone(); MAX_LINKS];
        mail.to = vec!["a".repeat(MAX_STRING); MAX_RECIPIENTS];
        let capped = cap(mail.clone());
        let size = json_len(&capped);
        assert!(size <= MAX_REQUEST, "{size}");
        assert!(
            size + json_len(&mail.links[0]) > MAX_REQUEST,
            "dropped too much"
        );
        assert!(capped.links.len() < MAX_LINKS && !capped.links.is_empty());
        assert_eq!(capped.to, mail.to);
        assert!(capped.truncated);

        // Control characters are six bytes each in JSON, so recipients alone can overflow.
        mail.links.clear();
        mail.to = vec!["\u{1}".repeat(MAX_STRING); MAX_RECIPIENTS];
        let capped = cap(mail);
        assert!(json_len(&capped) <= MAX_REQUEST);
        assert!(capped.links.is_empty() && capped.to.len() < MAX_RECIPIENTS);
        assert!(capped.truncated);
    }

    /// `len` characters cycling through every kind the padding rule counts.
    fn run(len: usize) -> String {
        "Az09+/=_-".chars().cycle().take(len).collect()
    }

    /// The body and `truncated` after `cap`, everything else in the mail well within its limits.
    fn capped_body(body: &str) -> (String, bool) {
        let mut mail: MailObservation = serde_json::from_value(mail()).unwrap();
        mail.body_text = body.to_string();
        let capped = cap(mail);
        (capped.body_text, capped.truncated)
    }

    // The cases are those listed in riggs-phish-padding.md, "What to test".
    #[test]
    fn padding_runs_over_256_characters_become_one_space_before_the_cut() {
        let sentence = " Your mailbox is full, sign in to keep it.";
        let expected = format!(" {sentence}");
        assert_eq!(
            capped_body(&format!("{}{sentence}", run(300))),
            (expected.clone(), true)
        );

        // Over the body limit only because of the run; the prose after it survives the cut.
        let padded = format!("Dear user,{}{sentence}", run(210_000));
        assert!(padded.len() > MAX_BODY_TEXT);
        assert_eq!(
            capped_body(&padded),
            (format!("Dear user, {sentence}"), true)
        );

        let between = " a word between ";
        assert_eq!(
            capped_body(&format!("{}{between}{}", run(300), run(1000))),
            (format!(" {between} "), true)
        );
    }

    #[test]
    fn runs_up_to_256_interrupted_runs_and_unspaced_scripts_are_kept() {
        assert_eq!(capped_body(&run(256)), (run(256), false));
        for separator in [" ", ".", "é"] {
            for before in [100, 255] {
                let body = format!("{}{separator}{}", run(before), run(256));
                assert_eq!(
                    capped_body(&body),
                    (body.clone(), false),
                    "{separator:?} {before}"
                );
            }
        }
        // 20,000 letters without a space, 60,000 bytes: under the body limit.
        let unspaced = "あいうえおかきくけこ".repeat(2000);
        assert_eq!(capped_body(&unspaced), (unspaced.clone(), false));
    }
}
