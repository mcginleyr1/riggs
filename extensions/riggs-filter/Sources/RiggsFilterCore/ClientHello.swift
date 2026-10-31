/// The SNI host name in the TLS ClientHello that opens an outbound stream, or
/// nil when `bytes` does not start with a complete ClientHello naming a DNS
/// host. Every length field is checked against the bytes actually present, so
/// truncated or hostile input yields nil, never a trap.
///
/// The name is whatever the client chose to send: it identifies the intended
/// destination of an honest client, not the server the socket reaches.
public func tlsServerName(_ bytes: [UInt8]) -> String? {
    var record = Reader(rest: bytes[...])
    guard record.int(1) == 0x16, record.int(1) == 0x03, record.int(1) != nil,  // handshake record, TLS 1.x
          var handshake = record.reader(lengthWidth: 2),
          handshake.int(1) == 0x01,  // ClientHello
          var hello = handshake.reader(lengthWidth: 3),
          hello.bytes(2 + 32) != nil,  // legacy_version, random
          hello.reader(lengthWidth: 1) != nil,  // legacy_session_id
          hello.reader(lengthWidth: 2) != nil,  // cipher_suites
          hello.reader(lengthWidth: 1) != nil,  // legacy_compression_methods
          var extensions = hello.reader(lengthWidth: 2)
    else { return nil }

    while let type = extensions.int(2), var body = extensions.reader(lengthWidth: 2) {
        guard type == 0 else { continue }  // server_name
        guard var names = body.reader(lengthWidth: 2) else { return nil }
        while let nameType = names.int(1), let name = names.bytes(names.int(2)) {
            if nameType == 0 { return hostName(name) }  // host_name
        }
        return nil
    }
    return nil
}

/// Size of the TLS handshake record `bytes` starts with (header included), so
/// a caller holding part of a ClientHello knows how much more to wait for.
/// nil when `bytes` does not start a handshake record of legal size.
public func tlsHandshakeRecordLength(_ bytes: [UInt8]) -> Int? {
    var record = Reader(rest: bytes[...])
    guard record.int(1) == 0x16, record.int(1) == 0x03, record.int(1) != nil,
          let length = record.int(2), length <= 1 << 14
    else { return nil }
    return 5 + length
}

/// True while `bytes` is too short to judge: under the 5-byte record header,
/// and every byte so far fits a TLS handshake record. TCP does not keep write
/// boundaries, so the first read can end mid-header; deciding on the IP then
/// would drop an allowed host (enforce) or skip DLP for the flow (monitor).
public func mayStartTLSHandshake(_ bytes: [UInt8]) -> Bool {
    bytes.count < 5 && bytes.first.map { $0 == 0x16 } != false
        && (bytes.count < 2 || bytes[1] == 0x03)
}

private func hostName(_ bytes: ArraySlice<UInt8>) -> String? {
    let name = String(decoding: bytes, as: UTF8.self)
    let valid = !name.isEmpty && name.utf8.count <= 253
        && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-._".contains($0)) }
    return valid ? name.lowercased() : nil
}

private struct Reader {
    var rest: ArraySlice<UInt8>

    mutating func bytes(_ count: Int?) -> ArraySlice<UInt8>? {
        guard let count, count <= rest.count else { return nil }
        defer { rest = rest.dropFirst(count) }
        return rest.prefix(count)
    }

    /// Big-endian unsigned integer `width` bytes wide (TLS uses 1 to 3).
    mutating func int(_ width: Int) -> Int? {
        bytes(width)?.reduce(0) { $0 << 8 | Int($1) }
    }

    /// The vector that follows a `lengthWidth`-byte length prefix.
    mutating func reader(lengthWidth: Int) -> Reader? {
        bytes(int(lengthWidth)).map { Reader(rest: $0) }
    }
}
