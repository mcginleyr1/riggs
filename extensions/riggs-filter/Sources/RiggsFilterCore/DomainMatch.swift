/// True when `host` matches one of `patterns`: an exact name ("claude.ai") or
/// a wildcard ("*.openai.com") that matches the bare domain and any subdomain.
/// Case-insensitive.
public func hostMatches(_ host: String, anyOf patterns: [String]) -> Bool {
    let host = host.lowercased()
    return patterns.contains { pattern in
        let pattern = pattern.lowercased()
        guard pattern.hasPrefix("*.") else { return host == pattern }
        return host.hasSuffix(pattern.dropFirst(1)) || host == pattern.dropFirst(2)
    }
}
