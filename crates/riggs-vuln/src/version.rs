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

        // Split off pre-release suffix at first '-' or first non-numeric after patch
        let (version_part, pre) = if let Some(idx) = s.find('-') {
            (&s[..idx], s[idx + 1..].to_string())
        } else {
            (s, String::new())
        };

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
                    (false, false) => self.pre.cmp(&other.pre),
                }
            })
    }
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
}
