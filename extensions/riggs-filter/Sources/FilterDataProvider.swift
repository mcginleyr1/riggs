import Darwin
import NetworkExtension
import os.log

/// NEFilterDataProvider subclass that intercepts network flows to monitored
/// domains and queries the Riggs daemon to decide whether to allow or block.
///
/// The filter does NOT inspect TLS payload content. Instead it correlates:
///   - The source PID (from the flow's audit token)
///   - The destination hostname (from SNI / NEFilterSocketFlow)
///
/// The daemon's DLP correlator knows which PIDs recently opened sensitive
/// files. If PID + watched domain match within the correlation window,
/// the flow is dropped.
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
        logger.info("starting DLP network filter")
        daemonConnection = DaemonConnection(socketPath: "/var/run/riggs.sock")
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.info("stopping DLP network filter (reason: \(String(describing: reason)))")
        daemonConnection?.disconnect()
        daemonConnection = nil
        completionHandler()
    }

    // MARK: - Flow handling

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        let hostname = socketFlow.remoteHostname ?? remoteHostname(from: socketFlow)
        let pid = extractPid(from: socketFlow)
        let remoteIP = socketFlow.remoteEndpoint.flatMap { endpoint -> String? in
            (endpoint as? NWHostEndpoint)?.hostname
        } ?? ""
        let remotePort = socketFlow.remoteEndpoint.flatMap { endpoint -> UInt16? in
            (endpoint as? NWHostEndpoint).flatMap { UInt16($0.port) }
        } ?? 0

        // No daemon -> fail open (never break the user's network on our account).
        guard let connection = daemonConnection else {
            return .allow()
        }

        // 1) Egress allowlist (default-deny) — evaluated for EVERY flow, keyed on
        //    the originating process. This is what catches an install script's
        //    beacon to C&C even when the destination looks innocuous.
        if pid > 0 {
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
                    "EGRESS BLOCK [\(egress.mode)]: pid \(pid) (\(processPath)) -> \(hostname ?? remoteIP): \(egress.reason ?? "policy")"
                )
                return .drop()
            }
        }

        // 2) DLP (content) — only for watched domains, once egress permits the flow.
        guard let hostname = hostname, isWatchedDomain(hostname), pid > 0 else {
            return .allow()
        }
        let verdict = connection.checkFlow(
            pid: pid,
            hostname: hostname,
            remoteIP: remoteIP,
            remotePort: remotePort
        )
        if verdict.allow {
            return .allow()
        }
        logger.warning("DLP BLOCK: PID \(pid) -> \(hostname): \(verdict.reason ?? "policy")")
        return .drop()
    }

    /// Resolve a PID's executable path via libproc (best-effort; "" on failure).
    private func processPath(for pid: UInt32) -> String {
        var buffer = [CChar](repeating: 0, count: 4096)
        let ret = proc_pidpath(Int32(pid), &buffer, UInt32(buffer.count))
        return ret > 0 ? String(cString: buffer) : ""
    }

    // MARK: - Domain matching

    private func isWatchedDomain(_ hostname: String) -> Bool {
        let lower = hostname.lowercased()
        for pattern in watchedDomains {
            let patternLower = pattern.lowercased()
            if patternLower.hasPrefix("*.") {
                let suffix = String(patternLower.dropFirst(1)) // ".example.com"
                let bare = String(patternLower.dropFirst(2))   // "example.com"
                if lower.hasSuffix(suffix) || lower == bare {
                    return true
                }
            } else if lower == patternLower {
                return true
            }
        }
        return false
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

    private func remoteHostname(from flow: NEFilterSocketFlow) -> String? {
        guard let endpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            return nil
        }
        return endpoint.hostname
    }
}
