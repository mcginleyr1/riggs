import Darwin
import NetworkExtension
import RiggsFilterCore
import os.log

/// NEFilterDataProvider subclass that asks the Riggs daemon whether each
/// network flow may proceed: the egress allowlist for every flow, then DLP
/// for flows to watched domains.
///
/// The filter does NOT inspect TLS payload content. It correlates:
///   - The source PID (from the flow's audit token)
///   - The destination hostname: NEFilterFlow.remoteHostname when the client
///     used Network.framework/NSURLSession, otherwise the SNI of the TLS
///     ClientHello the client sends first
///
/// The daemon's DLP correlator knows which PIDs recently opened sensitive
/// files. If PID + watched domain match within the correlation window,
/// the flow is dropped.
///
/// Any failure to reach the daemon allows the flow (fail-open, see
/// DaemonConnection): a dead daemon must never cut the user's network.
class FilterDataProvider: NEFilterDataProvider {

    private let logger = Logger(subsystem: "com.riggs.filter", category: "dlp")
    private var daemonConnection: DaemonConnection?

    // Domains loaded from daemon at startup and refreshed periodically.
    private var watchedDomains: [String] = [
        "claude.ai",
        "*.anthropic.com",
        "chatgpt.com",
        "*.openai.com",
    ]

    // MARK: - Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // NE providers are sandboxed. The daemon serves a root-only socket in
        // the app-group container we share with it (the documented sandbox
        // IPC path); /var/run/riggs.sock is the fallback, which macOS's
        // application.sb also lets sandboxed processes connect to.
        guard let group = Bundle.main.object(forInfoDictionaryKey: "RiggsAppGroup") as? String,
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        else {
            logger.fault("Info.plist has no RiggsAppGroup; filter not started")
            completionHandler(NSError(domain: "com.riggs.filter", code: 1))
            return
        }
        let socketPaths = [container.appendingPathComponent("riggs-filter.sock").path, "/var/run/riggs.sock"]
        logger.notice("starting network filter, daemon sockets: \(socketPaths, privacy: .public)")
        daemonConnection = DaemonConnection(socketPaths: socketPaths)
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.info("stopping network filter (reason: \(String(describing: reason)))")
        daemonConnection?.disconnect()
        daemonConnection = nil
        completionHandler()
    }

    // MARK: - Flow handling

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }
        // BSD-socket clients (npm, pip, cargo, git, curl) leave remoteHostname
        // nil. Hold their first outbound bytes (one maximal TLS record: 5-byte
        // header + 2^14) and decide once the ClientHello's SNI is readable.
        if socketFlow.remoteHostname == nil, socketFlow.socketProtocol == IPPROTO_TCP,
           socketFlow.direction == .outbound {
            return .filterDataVerdict(
                withFilterInbound: false, peekInboundBytes: 0,
                filterOutbound: true, peekOutboundBytes: 5 + (1 << 14)
            )
        }
        return allows(socketFlow, hostname: socketFlow.remoteHostname) ? .allow() : .drop()
    }

    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }
        let bytes = [UInt8](readBytes)
        if let hostname = tlsServerName(bytes) {
            return allows(socketFlow, hostname: hostname) ? .allow() : .drop()
        }
        // A ClientHello larger than this read (post-quantum key shares make
        // them span TCP segments): pass nothing yet, wait for the full record.
        if let recordLength = tlsHandshakeRecordLength(bytes), recordLength > bytes.count {
            return NEFilterDataVerdict(passBytes: 0, peekBytes: recordLength)
        }
        // Not TLS (ssh, plain HTTP, ...) or no SNI: the remote IP decides.
        return allows(socketFlow, hostname: nil) ? .allow() : .drop()
    }

    /// The client closed its sending side before a decision (e.g. a partial
    /// ClientHello): decide on the remote IP alone.
    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }
        return allows(socketFlow, hostname: nil) ? .allow() : .drop()
    }

    /// Egress allowlist, then DLP. `hostname` nil means only the IP is known.
    private func allows(_ flow: NEFilterSocketFlow, hostname: String?) -> Bool {
        let pid = extractPid(from: flow)
        let endpoint = flow.remoteEndpoint as? NWHostEndpoint
        let remoteIP = endpoint?.hostname ?? ""
        let remotePort = endpoint.flatMap { UInt16($0.port) } ?? 0

        // No daemon -> fail open (never break the user's network on our account).
        guard let connection = daemonConnection, pid > 0 else {
            return true
        }

        // 1) Egress allowlist (default-deny) — evaluated for EVERY flow, keyed on
        //    the originating process. This is what catches an install script's
        //    beacon to C&C even when the destination looks innocuous.
        let processPath = processPath(for: pid)
        let egress = connection.checkEgress(
            pid: pid,
            processPath: processPath,
            hostname: hostname ?? "",
            remoteIP: remoteIP,
            remotePort: remotePort
        )
        if !egress.allow {
            logger.warning(
                "EGRESS BLOCK [\(egress.mode, privacy: .public)]: pid \(pid) (\(processPath, privacy: .public)) -> \(hostname ?? remoteIP, privacy: .public):\(remotePort): \(egress.reason ?? "policy", privacy: .public)"
            )
            return false
        }

        // 2) DLP (content) — only for watched domains, once egress permits the flow.
        guard let hostname, hostMatches(hostname, anyOf: watchedDomains) else {
            return true
        }
        let verdict = connection.checkFlow(
            pid: pid,
            hostname: hostname,
            remoteIP: remoteIP,
            remotePort: remotePort
        )
        if !verdict.allow {
            logger.warning(
                "DLP BLOCK: PID \(pid) -> \(hostname, privacy: .public): \(verdict.reason ?? "policy", privacy: .public)"
            )
        }
        return verdict.allow
    }

    /// Resolve a PID's executable path via libproc (best-effort; "" on failure).
    private func processPath(for pid: UInt32) -> String {
        var buffer = [CChar](repeating: 0, count: 4096)
        let ret = proc_pidpath(Int32(pid), &buffer, UInt32(buffer.count))
        return ret > 0 ? String(cString: buffer) : ""
    }

    // MARK: - PID extraction

    private func extractPid(from flow: NEFilterSocketFlow) -> UInt32 {
        guard let token = flow.sourceAppAuditToken else { return 0 }
        // audit_token_t is 8 x UInt32. PID lives at index 5.
        return token.withUnsafeBytes { ptr in
            guard ptr.count >= 24 else { return 0 }  // 6 * 4 bytes
            let bound = ptr.bindMemory(to: UInt32.self)
            return bound[5]
        }
    }
}
