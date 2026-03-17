import Foundation
import os.log

/// Communicates with the Riggs daemon over a Unix domain socket using the
/// same length-prefixed JSON protocol that riggs-comms speaks.
///
/// Protocol: [4-byte LE length][JSON payload]
///
/// Request:  {"DlpCheckFlow":{"pid":1234,"remote_hostname":"claude.ai",...}}
/// Response: {"DlpVerdict":{"allow":false,"reason":"..."}}
class DaemonConnection {

    private let logger = Logger(subsystem: "com.riggs.filter", category: "daemon-conn")
    private let socketPath: String
    private let queue = DispatchQueue(label: "com.riggs.filter.daemon", qos: .userInteractive)

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    struct DlpVerdict {
        let allow: Bool
        let reason: String?
    }

    /// Query the daemon: should this PID's flow to this hostname be allowed?
    /// Synchronous -- blocks until the daemon responds or times out.
    /// Returns allow=true on any error (fail-open).
    func checkFlow(pid: UInt32, hostname: String, remoteIP: String, remotePort: UInt16) -> DlpVerdict {
        let safeHostname = sanitizeForJSON(hostname)
        let safeIP = sanitizeForJSON(remoteIP)
        let request = """
        {"DlpCheckFlow":{"pid":\(pid),"remote_hostname":"\(safeHostname)","remote_ip":"\(safeIP)","remote_port":\(remotePort)}}
        """

        guard let responseData = sendAndReceive(request) else {
            return DlpVerdict(allow: true, reason: nil)
        }

        return parseDlpVerdict(responseData)
    }

    func disconnect() {
        // Connection is per-request, nothing to tear down
    }

    // MARK: - Socket communication

    private func sendAndReceive(_ jsonString: String) -> Data? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            logger.error("failed to create socket: \(errno)")
            return nil
        }
        defer { close(fd) }

        // Set a 500ms timeout so we don't block the filter indefinitely
        var tv = timeval(tv_sec: 0, tv_usec: 500_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Connect
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            logger.error("socket path too long")
            return nil
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dest in
                for (i, byte) in pathBytes.enumerated() {
                    dest[i] = byte
                }
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            logger.warning("failed to connect to daemon socket: \(errno)")
            return nil
        }

        // Send: 4-byte LE length + JSON
        guard let payload = jsonString.data(using: .utf8) else { return nil }
        var length = UInt32(payload.count).littleEndian
        let lengthData = Data(bytes: &length, count: 4)

        guard sendAll(fd: fd, data: lengthData) && sendAll(fd: fd, data: payload) else {
            logger.warning("failed to send to daemon")
            return nil
        }

        // Receive: 4-byte LE length + JSON response
        guard let respLenData = recvExact(fd: fd, count: 4) else {
            logger.warning("failed to receive response length")
            return nil
        }
        let respLen = respLenData.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        guard respLen > 0, respLen < 1_000_000 else {
            logger.warning("invalid response length: \(respLen)")
            return nil
        }

        return recvExact(fd: fd, count: Int(respLen))
    }

    private func sendAll(fd: Int32, data: Data) -> Bool {
        data.withUnsafeBytes { ptr in
            var sent = 0
            while sent < data.count {
                let n = Darwin.send(fd, ptr.baseAddress! + sent, data.count - sent, 0)
                if n <= 0 { return false }
                sent += n
            }
            return true
        }
    }

    private func recvExact(fd: Int32, count: Int) -> Data? {
        var buffer = Data(count: count)
        var received = 0
        let result = buffer.withUnsafeMutableBytes { ptr in
            while received < count {
                let n = Darwin.recv(fd, ptr.baseAddress! + received, count - received, 0)
                if n <= 0 { return false }
                received += n
            }
            return true
        }
        return result ? buffer : nil
    }

    // MARK: - JSON parsing

    private func parseDlpVerdict(_ data: Data) -> DlpVerdict {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            logger.warning("failed to parse daemon response")
            return DlpVerdict(allow: true, reason: nil)
        }

        if let verdictDict = json["DlpVerdict"] as? [String: Any] {
            let allow = verdictDict["allow"] as? Bool ?? true
            let reason = verdictDict["reason"] as? String
            return DlpVerdict(allow: allow, reason: reason)
        }

        return DlpVerdict(allow: true, reason: nil)
    }

    /// Sanitize strings before embedding in JSON to prevent injection.
    private func sanitizeForJSON(_ str: String) -> String {
        str.replacingOccurrences(of: "\\", with: "\\\\")
           .replacingOccurrences(of: "\"", with: "\\\"")
           .replacingOccurrences(of: "\n", with: "\\n")
           .replacingOccurrences(of: "\r", with: "\\r")
           .replacingOccurrences(of: "\t", with: "\\t")
    }
}
