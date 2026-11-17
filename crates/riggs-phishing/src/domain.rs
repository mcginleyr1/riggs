use url::Host;

/// A host reduced to the parts the lookalike rules compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// Lowercase ASCII host, IDN labels in punycode.
    pub host: String,
    /// Registrable domain: the public suffix plus one label (ASCII).
    pub registrable: String,
    /// The registrable domain's own label (ASCII).
    pub label: String,
    /// The public suffix (ASCII). An unknown last label counts as a suffix, as in the PSL algorithm.
    pub suffix: String,
    /// `label` in Unicode.
    pub unicode: String,
    /// `unicode` folded through the UTS 39 confusable skeleton, then lowercased.
    pub fold: String,
}

/// The longest host name DNS can carry, in dotted text without a trailing dot (RFC 1035 section
/// 2.3.4: 255 octets in wire form).
pub(crate) const MAX_HOST_BYTES: usize = 253;
/// The longest label DNS can carry (RFC 1035 section 2.3.4). Without it one label of a 253-byte
/// host could hold 27 hyphen parts for the lookalike rules to compare.
pub(crate) const MAX_LABEL_BYTES: usize = 63;

/// `None` for an IP literal, a single label, a bare public suffix, a host longer than DNS allows,
/// or anything that is not a host name.
pub fn name(host: &str) -> Option<Name> {
    let host = host.strip_suffix('.').unwrap_or(host);
    // url's host parser lowercases, applies IDNA and recognises every IPv4 and IPv6 form, so an IP
    // literal never reaches psl, which would read `192.168.1.1` as the domain `1.1`. It checks no
    // length: it calls idna with `DnsLength::Ignore`.
    let Ok(Host::Domain(host)) = Host::parse(host) else {
        return None;
    };
    if host.len() > MAX_HOST_BYTES || host.split('.').any(|l| l.len() > MAX_LABEL_BYTES) {
        return None;
    }
    let registrable = psl::domain_str(&host)?.to_owned();
    let suffix = psl::suffix_str(&host)?.to_owned();
    let label = registrable
        .strip_suffix(&suffix)?
        .strip_suffix('.')?
        .to_owned();
    let unicode = idna::domain_to_unicode(&label).0;
    let fold = fold(&unicode);
    Some(Name {
        host,
        registrable,
        label,
        suffix,
        unicode,
        fold,
    })
}

pub fn fold(label: &str) -> String {
    unicode_security::skeleton(label)
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_splits_into_registrable_label_and_suffix() {
        let n = name("WWW.Example.co.uk.").unwrap();
        assert_eq!(n.host, "www.example.co.uk");
        assert_eq!(n.registrable, "example.co.uk");
        assert_eq!(n.label, "example");
        assert_eq!(n.suffix, "co.uk");
        assert_eq!(n.unicode, "example");
        assert_eq!(n.fold, "exarnple");
    }

    #[test]
    fn ip_literals_single_labels_and_bare_suffixes_have_no_name() {
        for host in [
            "192.168.1.1",
            "0x7f.1",
            "[::1]",
            "::1",
            "[2001:db8::1]",
            "localhost",
            "com",
            "co.uk",
            "",
            "example.com:443",
        ] {
            assert_eq!(name(host), None, "{host}");
        }
    }

    #[test]
    fn hosts_and_labels_longer_than_dns_allows_have_no_name() {
        let host = |last: usize| {
            format!(
                "{}.{}.{}.{}.com",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(last)
            )
        };
        assert_eq!(host(57).len(), 253);
        assert!(name(&host(57)).is_some());
        assert_eq!(name(&host(58)), None);
        assert!(name(&format!("{}.com", "a".repeat(63))).is_some());
        assert_eq!(name(&format!("{}.com", "a".repeat(64))), None);
    }

    #[test]
    fn an_unknown_suffix_is_one_label_as_in_the_psl_algorithm() {
        let n = name("intranet.corp.unknowntld").unwrap();
        assert_eq!(n.registrable, "corp.unknowntld");
        assert_eq!(n.suffix, "unknowntld");
        assert_eq!(n.label, "corp");
    }

    #[test]
    fn an_idn_host_is_punycode_with_its_unicode_label_folded() {
        // Cyrillic U+0430 in place of the Latin "a".
        let n = name("p\u{430}ypal.com").unwrap();
        assert!(n.registrable.starts_with("xn--"), "{}", n.registrable);
        assert!(n.registrable.ends_with(".com"));
        assert_eq!(n.unicode, "p\u{430}ypal");
        assert_eq!(n.fold, "paypal");
    }

    #[test]
    fn the_folding_merges_the_ascii_pairs_the_rules_rely_on() {
        assert_eq!(fold("rn"), fold("m"));
        assert_eq!(fold("l"), fold("1"));
        assert_eq!(fold("o"), fold("0"));
        assert_eq!(fold("bankofarnerica"), fold("bankofamerica"));
    }
}
