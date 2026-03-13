use std::path::Path;
use riggs_types::errors::RiggsError;
use crate::cve::VulnReport;

pub struct VulnScanner {
    _private: (),
}

impl VulnScanner {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub async fn scan_system(&self) -> Result<VulnReport, RiggsError> {
        todo!()
    }

    pub async fn scan_path(&self, _path: &Path) -> Result<VulnReport, RiggsError> {
        todo!()
    }

    pub async fn load_cve_database(&self, _path: &Path) -> Result<(), RiggsError> {
        todo!()
    }
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self::new()
    }
}
