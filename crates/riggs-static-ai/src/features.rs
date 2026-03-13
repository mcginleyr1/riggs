use std::fs;
use std::path::Path;

use goblin::Object;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FeatureError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct FileFeatures {
    pub file_size: u64,
    pub entropy: f32,
    pub section_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub has_debug_info: bool,
    pub is_packed: bool,
    pub section_entropies: Vec<f32>,
    pub suspicious_imports: Vec<String>,
    pub suspicious_strings: Vec<String>,
}

const SUSPICIOUS_IMPORT_NAMES: &[&str] = &[
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "LoadLibrary",
    "GetProcAddress",
    "WinExec",
    "ShellExecute",
    "URLDownloadToFile",
    "InternetOpen",
    "CryptEncrypt",
    "ptrace",
    "mprotect",
    "dlopen",
    "dlsym",
    "execve",
    "fork",
    "mmap",
];

const SUSPICIOUS_STRING_PATTERNS: &[&str] = &[
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "eval",
    "base64",
    "http://",
    "https://",
    "socket",
    "reverse",
    "shell",
    "exploit",
    "payload",
    "inject",
    "keylog",
    "ransom",
    "encrypt",
    "decrypt",
    "backdoor",
    "rootkit",
    "trojan",
    "bind_shell",
    "reverse_tcp",
    "meterpreter",
    "mimikatz",
    "passwd",
    "shadow",
    "credential",
    "dump",
];

/// Calculate Shannon entropy over a byte slice.
/// Returns a value in the range [0.0, 8.0] where 8.0 = maximum randomness.
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.len() < 2 {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    // Clamp to valid range — floating-point accumulation can drift slightly
    entropy.clamp(0.0, 8.0) as f32
}

/// Scan the raw bytes for printable ASCII strings that match known suspicious
/// patterns. Uses a simple sliding-window extraction of printable runs (length >= 4)
/// then checks each run against the pattern list, case-insensitively.
pub fn extract_suspicious_strings(bytes: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut current = Vec::new();

    let patterns_lower: Vec<String> = SUSPICIOUS_STRING_PATTERNS
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .collect();

    let check_and_collect = |run: &[u8], found: &mut Vec<String>, patterns: &[String]| {
        if run.len() < 4 {
            return;
        }
        let s = String::from_utf8_lossy(run);
        let lower = s.to_ascii_lowercase();
        for pat in patterns {
            if lower.contains(pat.as_str()) {
                let matched = s.to_string();
                if !found.contains(&matched) {
                    found.push(matched);
                }
                break;
            }
        }
    };

    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            check_and_collect(&current, &mut found, &patterns_lower);
            current.clear();
        }
    }
    // Final run
    check_and_collect(&current, &mut found, &patterns_lower);

    found
}

impl FileFeatures {
    pub fn extract(path: &Path) -> Result<Self, FeatureError> {
        let bytes = fs::read(path)?;
        Self::extract_from_bytes(&bytes)
    }

    pub fn extract_from_bytes(bytes: &[u8]) -> Result<Self, FeatureError> {
        let file_size = bytes.len() as u64;
        let entropy = calculate_entropy(bytes);
        let suspicious_strings = extract_suspicious_strings(bytes);

        let object = match Object::parse(bytes) {
            Ok(o) => o,
            Err(_) => {
                // Gracefully handle unparseable binaries — return what we can
                return Ok(Self {
                    file_size,
                    entropy,
                    section_count: 0,
                    import_count: 0,
                    export_count: 0,
                    has_debug_info: false,
                    is_packed: entropy > 7.0,
                    section_entropies: Vec::new(),
                    suspicious_imports: Vec::new(),
                    suspicious_strings,
                });
            }
        };

        match object {
            Object::PE(pe) => Self::from_pe(&pe, bytes, file_size, entropy, suspicious_strings),
            Object::Elf(elf) => {
                Self::from_elf(&elf, bytes, file_size, entropy, suspicious_strings)
            }
            Object::Mach(mach) => {
                Self::from_mach(&mach, bytes, file_size, entropy, suspicious_strings)
            }
            _ => Ok(Self {
                file_size,
                entropy,
                section_count: 0,
                import_count: 0,
                export_count: 0,
                has_debug_info: false,
                is_packed: entropy > 7.0,
                section_entropies: Vec::new(),
                suspicious_imports: Vec::new(),
                suspicious_strings,
            }),
        }
    }

    /// Convert features into a flat f32 vector suitable for ML inference.
    /// All values are normalized to the 0.0-1.0 range.
    pub fn to_feature_vector(&self) -> Vec<f32> {
        let mut v = Vec::with_capacity(16);

        // file_size: log-scale normalization (cap at ~1 GB)
        let max_log_size: f32 = (1_073_741_824.0_f64).ln() as f32; // ln(1 GB)
        let log_size = if self.file_size > 0 {
            (self.file_size as f64).ln() as f32 / max_log_size
        } else {
            0.0
        };
        v.push(log_size.clamp(0.0, 1.0));

        // entropy: divide by theoretical max (8.0)
        v.push((self.entropy / 8.0).clamp(0.0, 1.0));

        // section_count: normalize against a reasonable max (64 sections)
        v.push((self.section_count as f32 / 64.0).clamp(0.0, 1.0));

        // import_count: normalize against a reasonable max (2048 imports)
        v.push((self.import_count as f32 / 2048.0).clamp(0.0, 1.0));

        // export_count: normalize against a reasonable max (2048 exports)
        v.push((self.export_count as f32 / 2048.0).clamp(0.0, 1.0));

        // has_debug_info: boolean
        v.push(if self.has_debug_info { 1.0 } else { 0.0 });

        // is_packed: boolean
        v.push(if self.is_packed { 1.0 } else { 0.0 });

        // max section entropy / 8.0
        let max_section_entropy = self
            .section_entropies
            .iter()
            .copied()
            .fold(0.0_f32, f32::max);
        v.push((max_section_entropy / 8.0).clamp(0.0, 1.0));

        // min section entropy / 8.0
        let min_section_entropy = self
            .section_entropies
            .iter()
            .copied()
            .fold(8.0_f32, f32::min);
        let min_se = if self.section_entropies.is_empty() {
            0.0
        } else {
            min_section_entropy / 8.0
        };
        v.push(min_se.clamp(0.0, 1.0));

        // mean section entropy / 8.0
        let mean_section_entropy = if self.section_entropies.is_empty() {
            0.0
        } else {
            let sum: f32 = self.section_entropies.iter().sum();
            sum / self.section_entropies.len() as f32 / 8.0
        };
        v.push(mean_section_entropy.clamp(0.0, 1.0));

        // suspicious_import ratio: how many of the known-bad names we hit
        let suspicious_ratio =
            self.suspicious_imports.len() as f32 / SUSPICIOUS_IMPORT_NAMES.len() as f32;
        v.push(suspicious_ratio.clamp(0.0, 1.0));

        // suspicious_string count normalized (cap at 20)
        v.push((self.suspicious_strings.len() as f32 / 20.0).clamp(0.0, 1.0));

        v
    }

    /// Pure-heuristic threat score in [0.0, 1.0].
    /// Higher values indicate a greater likelihood of malicious intent.
    pub fn heuristic_score(&self) -> f32 {
        let mut score: f32 = 0.0;
        let mut weight_sum: f32 = 0.0;

        // Entropy contribution (weight 0.25)
        // High overall entropy is suspicious — compressed or encrypted payloads.
        let entropy_signal = (self.entropy / 8.0).clamp(0.0, 1.0);
        score += 0.25 * entropy_signal;
        weight_sum += 0.25;

        // Packed detection (weight 0.2)
        if self.is_packed {
            score += 0.2;
        }
        weight_sum += 0.2;

        // Suspicious imports (weight 0.2)
        let import_signal = (self.suspicious_imports.len() as f32 / 5.0).clamp(0.0, 1.0);
        score += 0.2 * import_signal;
        weight_sum += 0.2;

        // Suspicious strings (weight 0.15)
        let string_signal = (self.suspicious_strings.len() as f32 / 5.0).clamp(0.0, 1.0);
        score += 0.15 * string_signal;
        weight_sum += 0.15;

        // Low section count is anomalous for non-trivial binaries (weight 0.1)
        // Very few sections (1-2) combined with nontrivial file size is suspicious
        let section_signal = if self.file_size > 4096 && self.section_count <= 2 {
            1.0
        } else if self.section_count <= 4 {
            0.3
        } else {
            0.0
        };
        score += 0.1 * section_signal;
        weight_sum += 0.1;

        // No debug info on a non-trivial binary (weight 0.05)
        if !self.has_debug_info && self.file_size > 4096 {
            score += 0.05;
        }
        weight_sum += 0.05;

        // Very small import table for a non-trivial binary (weight 0.05)
        // Could indicate the binary resolves imports dynamically (suspicious)
        let low_import_signal = if self.file_size > 10_000 && self.import_count < 5 {
            1.0
        } else {
            0.0
        };
        score += 0.05 * low_import_signal;
        weight_sum += 0.05;

        (score / weight_sum).clamp(0.0, 1.0)
    }

    fn from_pe(
        pe: &goblin::pe::PE,
        bytes: &[u8],
        file_size: u64,
        entropy: f32,
        suspicious_strings: Vec<String>,
    ) -> Result<Self, FeatureError> {
        let sections = &pe.sections;
        let section_count = sections.len();

        let section_entropies: Vec<f32> = sections
            .iter()
            .map(|s| {
                let offset = s.pointer_to_raw_data as usize;
                let size = s.size_of_raw_data as usize;
                let end = (offset + size).min(bytes.len());
                if offset < bytes.len() {
                    calculate_entropy(&bytes[offset..end])
                } else {
                    0.0
                }
            })
            .collect();

        let mut import_names: Vec<String> = Vec::new();
        for import in &pe.imports {
            import_names.push(import.name.to_string());
        }

        let import_count = import_names.len();
        let export_count = pe.exports.len();

        let suspicious_imports: Vec<String> = import_names
            .iter()
            .filter(|name| {
                SUSPICIOUS_IMPORT_NAMES
                    .iter()
                    .any(|s| name.contains(s))
            })
            .cloned()
            .collect();

        let has_debug_info = pe.debug_data.is_some();

        let is_packed = section_entropies.iter().any(|&e| e > 7.0)
            || (section_count <= 2 && entropy > 6.8);

        Ok(Self {
            file_size,
            entropy,
            section_count,
            import_count,
            export_count,
            has_debug_info,
            is_packed,
            section_entropies,
            suspicious_imports,
            suspicious_strings,
        })
    }

    fn from_elf(
        elf: &goblin::elf::Elf,
        bytes: &[u8],
        file_size: u64,
        entropy: f32,
        suspicious_strings: Vec<String>,
    ) -> Result<Self, FeatureError> {
        let section_count = elf.section_headers.len();

        let section_entropies: Vec<f32> = elf
            .section_headers
            .iter()
            .map(|sh| {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                let end = (offset + size).min(bytes.len());
                if offset < bytes.len() && size > 0 {
                    calculate_entropy(&bytes[offset..end])
                } else {
                    0.0
                }
            })
            .collect();

        let mut import_names: Vec<String> = Vec::new();
        for sym in &elf.dynsyms {
            if sym.is_import() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    import_names.push(name.to_string());
                }
            }
        }

        let export_count = elf
            .dynsyms
            .iter()
            .filter(|sym| !sym.is_import() && sym.st_value != 0)
            .count();

        let import_count = import_names.len();

        let suspicious_imports: Vec<String> = import_names
            .iter()
            .filter(|name| {
                SUSPICIOUS_IMPORT_NAMES
                    .iter()
                    .any(|s| name.contains(s))
            })
            .cloned()
            .collect();

        let has_debug_info = elf
            .section_headers
            .iter()
            .any(|sh| {
                elf.shdr_strtab
                    .get_at(sh.sh_name)
                    .map(|n| n.starts_with(".debug"))
                    .unwrap_or(false)
            });

        let is_packed = section_entropies.iter().any(|&e| e > 7.0)
            || (section_count <= 3 && entropy > 6.8);

        Ok(Self {
            file_size,
            entropy,
            section_count,
            import_count,
            export_count,
            has_debug_info,
            is_packed,
            section_entropies,
            suspicious_imports,
            suspicious_strings,
        })
    }

    fn from_mach(
        mach: &goblin::mach::Mach,
        bytes: &[u8],
        file_size: u64,
        entropy: f32,
        suspicious_strings: Vec<String>,
    ) -> Result<Self, FeatureError> {
        let macho = match mach {
            goblin::mach::Mach::Binary(m) => m,
            goblin::mach::Mach::Fat(fat) => {
                match fat.get(0) {
                    Ok(goblin::mach::SingleArch::MachO(m)) => {
                        return Self::from_single_macho(
                            &m,
                            bytes,
                            file_size,
                            entropy,
                            suspicious_strings,
                        );
                    }
                    _ => {
                        return Ok(Self {
                            file_size,
                            entropy,
                            section_count: 0,
                            import_count: 0,
                            export_count: 0,
                            has_debug_info: false,
                            is_packed: entropy > 7.0,
                            section_entropies: Vec::new(),
                            suspicious_imports: Vec::new(),
                            suspicious_strings,
                        });
                    }
                }
            }
        };

        Self::from_single_macho(macho, bytes, file_size, entropy, suspicious_strings)
    }

    fn from_single_macho(
        macho: &goblin::mach::MachO,
        bytes: &[u8],
        file_size: u64,
        entropy: f32,
        suspicious_strings: Vec<String>,
    ) -> Result<Self, FeatureError> {
        let mut section_count = 0;
        let mut section_entropies = Vec::new();

        for segment in &macho.segments {
            for (section, _) in segment.sections().unwrap_or_default() {
                section_count += 1;
                let offset = section.offset as usize;
                let size = section.size as usize;
                let end = (offset + size).min(bytes.len());
                if offset < bytes.len() && size > 0 {
                    section_entropies.push(calculate_entropy(&bytes[offset..end]));
                } else {
                    section_entropies.push(0.0);
                }
            }
        }

        let mut import_names: Vec<String> = Vec::new();
        if let Ok(imports) = macho.imports() {
            for imp in imports {
                import_names.push(imp.name.to_string());
            }
        }

        let export_count = macho.exports().map(|e| e.len()).unwrap_or(0);

        let import_count = import_names.len();

        let suspicious_imports: Vec<String> = import_names
            .iter()
            .filter(|name| {
                SUSPICIOUS_IMPORT_NAMES
                    .iter()
                    .any(|s| name.contains(s))
            })
            .cloned()
            .collect();

        let has_debug_info = macho
            .segments
            .iter()
            .any(|seg| seg.name().map(|n| n == "__DWARF").unwrap_or(false));

        let is_packed =
            section_entropies.iter().any(|&e| e > 7.0) || entropy > 7.0;

        Ok(Self {
            file_size,
            entropy,
            section_count,
            import_count,
            export_count,
            has_debug_info,
            is_packed,
            section_entropies,
            suspicious_imports,
            suspicious_strings,
        })
    }
}
