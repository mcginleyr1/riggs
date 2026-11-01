import RiggsFilterCore
import XCTest

final class DomainMatchTests: XCTestCase {
    let patterns = ["claude.ai", "*.openai.com"]

    func testExactAndWildcardMatches() {
        XCTAssertTrue(hostMatches("claude.ai", anyOf: patterns))
        XCTAssertTrue(hostMatches("CLAUDE.AI", anyOf: patterns))
        XCTAssertTrue(hostMatches("openai.com", anyOf: patterns))
        XCTAssertTrue(hostMatches("api.openai.com", anyOf: patterns))
        XCTAssertTrue(hostMatches("a.b.openai.com", anyOf: patterns))
    }

    func testLookalikesDoNotMatch() {
        XCTAssertFalse(hostMatches("evilclaude.ai", anyOf: patterns))
        XCTAssertFalse(hostMatches("api.claude.ai", anyOf: patterns))
        XCTAssertFalse(hostMatches("notopenai.com", anyOf: patterns))
        XCTAssertFalse(hostMatches("openai.com.evil.net", anyOf: patterns))
        XCTAssertFalse(hostMatches("", anyOf: patterns))
    }
}
