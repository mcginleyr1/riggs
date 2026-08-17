use std::cmp::Ordering;
use std::fmt;

/// Semantic version with comparison support for vulnerability matching.
/// Handles versions like "1.2.3", "1.2.3-beta1", "2.0.0rc1".
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: String,
    pub raw: String,
}

impl Version {
    pub fn parse(s: &str) -> Option<Self> {
        let raw = s.to_string();
        let s = s.trim().trim_start_matches('v').trim_start_matches('V');

        // Strip a Debian/dpkg epoch prefix ("2:1.2.3-1" -> "1.2.3-1").
        let s = match s.split_once(':') {
            Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
                rest
            }
            _ => s,
        };

        // The numeric core ends at the first '-'/'+' or the first character that
        // is neither a digit nor a dot. Everything after is the pre-release, so
        // "1.2.3-beta1" and "2.0.0rc1" both capture their suffix.
        let core_end = s
            .find(['-', '+'])
            .or_else(|| s.find(|c: char| !c.is_ascii_digit() && c != '.'))
            .unwrap_or(s.len());

        let version_part = &s[..core_end];
        let pre = s[core_end..].trim_start_matches(['-', '+']).to_string();

        let parts: Vec<&str> = version_part.split('.').collect();
        let major = parts.first().and_then(|p| parse_leading_digits(p))?;
        let minor = parts.get(1).and_then(|p| parse_leading_digits(p)).unwrap_or(0);
        let patch = parts.get(2).and_then(|p| parse_leading_digits(p)).unwrap_or(0);

        Some(Self {
            major,
            minor,
            patch,
            pre,
            raw,
        })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /// Check if this version falls within a range [start, end).
    /// If start is None, there's no lower bound.
    /// If end is None, there's no upper bound.
    pub fn in_range(&self, start: Option<&Version>, end: Option<&Version>) -> bool {
        if let Some(s) = start {
            if self < s {
                return false;
            }
        }
        if let Some(e) = end {
            if self >= e {
                return false;
            }
        }
        true
    }
}

fn parse_leading_digits(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| {
                // No pre-release > has pre-release (1.0.0 > 1.0.0-beta)
                match (self.pre.is_empty(), other.pre.is_empty()) {
                    (true, true) => Ordering::Equal,
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    (false, false) => cmp_prerelease(&self.pre, &other.pre),
                }
            })
    }
}

/// A pre-release identifier segment: numeric runs compare as numbers, so
/// "beta10" > "beta2" instead of sorting lexically.
enum PreSeg {
    Num(u64),
    Text(String),
}

fn prerelease_segments(s: &str) -> Vec<PreSeg> {
    let mut segs = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut run = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    run.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            segs.push(PreSeg::Num(run.parse().unwrap_or(0)));
        } else {
            let mut run = String::new();
            while let Some(&d) = chars.peek() {
                if !d.is_ascii_digit() {
                    run.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            segs.push(PreSeg::Text(run));
        }
    }
    segs
}

fn cmp_prerelease(a: &str, b: &str) -> Ordering {
    let sa = prerelease_segments(a);
    let sb = prerelease_segments(b);
    for (x, y) in sa.iter().zip(sb.iter()) {
        let ord = match (x, y) {
            (PreSeg::Num(m), PreSeg::Num(n)) => m.cmp(n),
            (PreSeg::Text(m), PreSeg::Text(n)) => m.cmp(n),
            // Numeric identifiers rank below alphanumeric ones (SemVer).
            (PreSeg::Num(_), PreSeg::Text(_)) => Ordering::Less,
            (PreSeg::Text(_), PreSeg::Num(_)) => Ordering::Greater,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    sa.len().cmp(&sb.len())
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pre.is_empty() {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, self.pre)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.pre.is_empty());
    }

    #[test]
    fn parse_with_v_prefix() {
        let v = Version::parse("v2.0.1").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 1);
    }

    #[test]
    fn parse_prerelease() {
        let v = Version::parse("1.0.0-beta1").unwrap();
        assert_eq!(v.pre, "beta1");
        assert!(v.is_prerelease());
    }

    #[test]
    fn parse_two_part() {
        let v = Version::parse("3.11").unwrap();
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 11);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn ordering() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.0.1").unwrap();
        let v3 = Version::parse("1.1.0").unwrap();
        let v4 = Version::parse("2.0.0").unwrap();
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }

    #[test]
    fn prerelease_ordering() {
        let release = Version::parse("1.0.0").unwrap();
        let beta = Version::parse("1.0.0-beta").unwrap();
        assert!(beta < release);
    }

    #[test]
    fn range_check() {
        let v = Version::parse("1.5.0").unwrap();
        let start = Version::parse("1.0.0").unwrap();
        let end = Version::parse("2.0.0").unwrap();
        assert!(v.in_range(Some(&start), Some(&end)));
        assert!(!v.in_range(Some(&end), None));
    }

    #[test]
    fn parse_dashless_prerelease() {
        let v = Version::parse("2.0.0rc1").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 0, 0));
        assert_eq!(v.pre, "rc1");
        assert!(v.is_prerelease());
        // A dashless pre-release must still rank below the final release.
        assert!(v < Version::parse("2.0.0").unwrap());
    }

    #[test]
    fn prerelease_numeric_ordering() {
        // Byte-lexical ordering would wrongly put beta10 < beta2.
        assert!(Version::parse("1.0.0-beta2").unwrap() < Version::parse("1.0.0-beta10").unwrap());
        assert!(Version::parse("1.0.0-rc2").unwrap() < Version::parse("1.0.0-rc10").unwrap());
    }

    #[test]
    fn parse_strips_debian_epoch() {
        let v = Version::parse("2:1.2.3-1ubuntu0.1").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (1, 2, 3));
    }
}
