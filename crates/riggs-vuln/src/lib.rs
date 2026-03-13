mod scanner;
mod cve;

pub use scanner::VulnScanner;
pub use cve::{Cve, CveSeverity, VulnReport};
