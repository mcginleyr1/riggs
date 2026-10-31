import RiggsFilterCore
import XCTest

final class ClientHelloTests: XCTestCase {

    /// First TLS records node 25 (OpenSSL, post-quantum key share: larger than
    /// one TCP segment) and macOS curl (LibreSSL) sent to a local listener.
    func testRealClientHellos() throws {
        for client in ["node25", "macos-curl"] {
            let url = try XCTUnwrap(Bundle.module.url(
                forResource: "\(client)-registry.npmjs.org", withExtension: "hex", subdirectory: "Fixtures"))
            let hex = try String(contentsOf: url, encoding: .utf8)
            let bytes = stride(from: 0, to: hex.count - 1, by: 2).map {
                UInt8(hex.dropFirst($0).prefix(2), radix: 16)!
            }
            XCTAssertEqual(tlsServerName(bytes), "registry.npmjs.org", client)
            XCTAssertEqual(tlsHandshakeRecordLength(Array(bytes.prefix(1448))), bytes.count, client)
        }
    }

    func testReadsServerName() {
        XCTAssertEqual(tlsServerName(clientHello(sni: "Registry.NPMjs.org")), "registry.npmjs.org")
    }

    func testFindsServerNameAfterOtherExtensions() {
        let supportedVersions = ext(0x002B, [0x02, 0x03, 0x04])
        let alpn = ext(0x0010, vec2(vec1(Array("h2".utf8))))
        let hello = clientHello(extensions: supportedVersions + alpn + serverName("pypi.org"))
        XCTAssertEqual(tlsServerName(hello), "pypi.org")
    }

    func testNoServerNameExtension() {
        XCTAssertNil(tlsServerName(clientHello(extensions: ext(0x002B, [0x02, 0x03, 0x04]))))
    }

    func testRejectsNamesThatAreNotDNSHosts() {
        for name in ["", "evil host.com", "a\u{0}b.com", "bücher.de", "x\"y.com", String(repeating: "a", count: 254)] {
            XCTAssertNil(tlsServerName(clientHello(sni: name)), name)
        }
    }

    func testEveryTruncationIsNil() {
        let hello = clientHello(sni: "crates.io")
        for count in 0..<hello.count {
            XCTAssertNil(tlsServerName(Array(hello.prefix(count))), "prefix \(count)")
        }
    }

    func testRecordLengthTellsHowMuchToWaitFor() {
        let hello = clientHello(sni: "github.com")
        XCTAssertNil(tlsHandshakeRecordLength(Array(hello.prefix(4))))
        for count in 5...hello.count {
            XCTAssertEqual(tlsHandshakeRecordLength(Array(hello.prefix(count))), hello.count)
        }
    }

    func testNonTLSStreams() {
        for stream in ["SSH-2.0-OpenSSH_9.9\r\n", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"] {
            XCTAssertNil(tlsServerName(Array(stream.utf8)))
            XCTAssertNil(tlsHandshakeRecordLength(Array(stream.utf8)))
        }
    }

    func testRecordLargerThanTLSAllowsIsRejected() {
        XCTAssertNil(tlsHandshakeRecordLength([0x16, 0x03, 0x01, 0x40, 0x01]))
    }

    func testLengthsThatOverrunTheirParentAreNil() {
        var hello = clientHello(sni: "example.com")
        hello[8] = 0xFF  // ClientHello body length past the end of the record
        XCTAssertNil(tlsServerName(hello))
    }

    func testCorruptingAnyByteNeverTraps() {
        let hello = clientHello(sni: "registry.npmjs.org")
        for index in hello.indices {
            for value: UInt8 in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
                var corrupt = hello
                corrupt[index] = value
                _ = tlsServerName(corrupt)
                _ = tlsHandshakeRecordLength(corrupt)
            }
        }
    }

    func testRandomInputNeverTraps() {
        var state: UInt64 = 0x9E37_79B9_7F4A_7C15
        for _ in 0..<5_000 {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            let count = Int(state >> 54)
            var bytes = (0..<count).map { i in UInt8(truncatingIfNeeded: (state >> (i % 56)) &+ UInt64(i)) }
            if count > 0 { bytes[0] = 0x16 }
            _ = tlsServerName(bytes)
            _ = tlsHandshakeRecordLength(bytes)
        }
    }
}

// MARK: - ClientHello construction

private func clientHello(sni: String) -> [UInt8] {
    clientHello(extensions: serverName(sni))
}

private func clientHello(extensions: [UInt8]) -> [UInt8] {
    let body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 0xAB, count: 32)
        + vec1([UInt8](repeating: 0xCD, count: 32))  // session id
        + vec2([0x13, 0x01, 0x13, 0x02])  // cipher suites
        + vec1([0x00])  // compression
        + vec2(extensions)
    let handshake = [0x01] + length(body.count, width: 3) + body
    return [0x16, 0x03, 0x01] + length(handshake.count, width: 2) + handshake
}

private func serverName(_ name: String) -> [UInt8] {
    ext(0x0000, vec2([0x00] + vec2(Array(name.utf8))))
}

private func ext(_ type: Int, _ data: [UInt8]) -> [UInt8] {
    length(type, width: 2) + vec2(data)
}

private func vec1(_ data: [UInt8]) -> [UInt8] { length(data.count, width: 1) + data }
private func vec2(_ data: [UInt8]) -> [UInt8] { length(data.count, width: 2) + data }

private func length(_ value: Int, width: Int) -> [UInt8] {
    (0..<width).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
}
