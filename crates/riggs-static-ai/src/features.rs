use std::fs;
use std::path::Path;

use goblin::mach::constants::{SECTION_TYPE, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL, S_ZEROFILL};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::symbols::{N_EXT, N_STAB, N_TYPE, N_UNDF};
use goblin::mach::MachO;
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

/// Entropy of each `(offset, size)` section, clipped to the file. Offsets and
/// sizes come from attacker-controlled headers, so at most two passes over the
/// file are hashed in total: thousands of whole-file sections would otherwise
/// cost one pass each. A well-formed table never claims more (callers pass
/// sections without file bytes as empty), so one that does reports `overrun`
/// and is treated as packed, rather than letting decoy sections spend the
/// budget ahead of a packed one.
fn entropy_by_section(
    bytes: &[u8],
    sections: impl IntoIterator<Item = (u64, u64)>,
) -> (Vec<f32>, bool) {
    let mut budget = bytes.len().saturating_mul(2);
    let mut overrun = false;
    let entropies = sections
        .into_iter()
        .map(|(offset, size)| {
            let start = usize::try_from(offset).map_or(bytes.len(), |o| o.min(bytes.len()));
            let len = usize::try_from(size)
                .unwrap_or(usize::MAX)
                .min(bytes.len() - start);
            if len > budget {
                overrun = true;
                return 0.0;
            }
            budget -= len;
            calculate_entropy(&bytes[start..start + len])
        })
        .collect();
    (entropies, overrun)
}

/// The suspicious names among `names`, examining at most `budget` bytes of
/// them in total: many imports can alias one long, crafted name.
fn find_suspicious_imports<'a>(
    names: impl IntoIterator<Item = &'a str>,
    mut budget: usize,
) -> Vec<String> {
    let mut found = Vec::new();
    for name in names {
        let Some(left) = budget.checked_sub(name.len()) else {
            break;
        };
        budget = left;
        if SUSPICIOUS_IMPORT_NAMES.iter().any(|s| name.contains(s)) {
            found.push(name.to_string());
        }
    }
    found
}

/// Imported symbol names, the import count and the export count, read straight
/// from LC_SYMTAB. goblin's export-trie walker recurses without a cycle check
/// (a 64-byte file overflows the stack and aborts the process) and its
/// bind-opcode interpreter loops on a count taken from the file, so neither is
/// used. Name lookups read at most `bytes.len()` bytes in total.
fn macho_symbols<'a>(macho: &MachO, bytes: &'a [u8]) -> (Vec<&'a str>, usize, usize) {
    let Some(symtab) = macho.load_commands.iter().find_map(|lc| match lc.command {
        CommandVariant::Symtab(st) => Some(st),
        _ => None,
    }) else {
        return (Vec::new(), 0, 0);
    };
    let strtab = bytes.get(symtab.stroff as usize..).unwrap_or_default();
    let entries = bytes.get(symtab.symoff as usize..).unwrap_or_default();
    let mut budget = bytes.len();
    let (mut names, mut imports, mut exports) = (Vec::new(), 0, 0);
    for nlist in entries
        .chunks_exact(if macho.is_64 { 16 } else { 12 })
        .take(symtab.nsyms as usize)
    {
        let n_type = nlist[4];
        if n_type & N_STAB != 0 || n_type & N_EXT == 0 {
            continue;
        }
        if n_type & N_TYPE != N_UNDF {
            exports += 1;
            continue;
        }
        imports += 1;
        let strx = [nlist[0], nlist[1], nlist[2], nlist[3]];
        let strx = if macho.little_endian {
            u32::from_le_bytes(strx)
        } else {
            u32::from_be_bytes(strx)
        };
        let tail = strtab.get(strx as usize..).unwrap_or_default();
        let window = &tail[..tail.len().min(budget)];
        match window.iter().position(|&b| b == 0) {
            Some(end) => {
                budget -= end + 1;
                if let Ok(name) = std::str::from_utf8(&window[..end]) {
                    names.push(name);
                }
            }
            None => budget = 0,
        }
    }
    (names, imports, exports)
}

/// Collection stops at this many distinct matches: the scores only use
/// min(count, 20) and min(count, 5), and an unbounded list made the
/// deduplication quadratic on files crafted with many distinct matches.
const MAX_SUSPICIOUS_STRINGS: usize = 20;

/// Scan the raw bytes for printable ASCII strings that match known suspicious
/// patterns. Uses a simple sliding-window extraction of printable runs (length >= 4)
/// then checks each run against the pattern list, case-insensitively. Returns at
/// most `MAX_SUSPICIOUS_STRINGS` distinct matches.
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
            if found.len() == MAX_SUSPICIOUS_STRINGS {
                return found;
            }
            current.clear();
        }
    }
    // Final run
    check_and_collect(&current, &mut found, &patterns_lower);

    found
}

/// Default cap on how many bytes of a file are read for static analysis, so a
/// huge file can't blow up memory. Malware headers/strings live well within
/// this; operators can override via [engine].static_ai_max_scan_mib.
pub const DEFAULT_MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

impl FileFeatures {
    pub fn extract(path: &Path) -> Result<Self, FeatureError> {
        Self::extract_with_limit(path, DEFAULT_MAX_SCAN_BYTES)
    }

    pub fn extract_with_limit(path: &Path, max_bytes: u64) -> Result<Self, FeatureError> {
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(max_bytes)
            .read_to_end(&mut bytes)?;
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
            Object::Elf(elf) => Self::from_elf(&elf, bytes, file_size, entropy, suspicious_strings),
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

        let (section_entropies, overrun) = entropy_by_section(
            bytes,
            sections.iter().map(|s| {
                (
                    u64::from(s.pointer_to_raw_data),
                    u64::from(s.size_of_raw_data),
                )
            }),
        );

        let import_count = pe.imports.len();
        let export_count = pe.exports.len();
        let suspicious_imports =
            find_suspicious_imports(pe.imports.iter().map(|i| &*i.name), bytes.len());

        let has_debug_info = pe.debug_data.is_some();

        let is_packed = overrun
            || section_entropies.iter().any(|&e| e > 7.0)
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

        let (section_entropies, overrun) = entropy_by_section(
            bytes,
            elf.section_headers.iter().map(|sh| {
                // NOBITS sections (.bss, .tbss) have no bytes in the file.
                if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                    (0, 0)
                } else {
                    (sh.sh_offset, sh.sh_size)
                }
            }),
        );

        let import_names: Vec<&str> = elf
            .dynsyms
            .iter()
            .filter(|sym| sym.is_import())
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
            .collect();

        let export_count = elf
            .dynsyms
            .iter()
            .filter(|sym| !sym.is_import() && sym.st_value != 0)
            .count();

        let import_count = import_names.len();
        let suspicious_imports = find_suspicious_imports(import_names, bytes.len());

        let has_debug_info = elf.section_headers.iter().any(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|n| n.starts_with(".debug"))
                .unwrap_or(false)
        });

        let is_packed = overrun
            || section_entropies.iter().any(|&e| e > 7.0)
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
            goblin::mach::Mach::Fat(fat) => match (fat.iter_arches().next(), fat.get(0)) {
                // Offsets inside a fat binary are relative to its arch slice.
                (Some(Ok(arch)), Ok(goblin::mach::SingleArch::MachO(m))) => {
                    return Self::from_single_macho(
                        &m,
                        arch.slice(bytes),
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
            },
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
        let sections: Vec<(u64, u64)> = macho
            .segments
            .iter()
            .flat_map(|segment| segment.sections().unwrap_or_default())
            .map(|(section, _)| {
                // Zerofill sections (__bss, __common) have no bytes in the file.
                let zerofill = matches!(
                    section.flags & SECTION_TYPE,
                    S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
                );
                if zerofill {
                    (0, 0)
                } else {
                    (u64::from(section.offset), section.size)
                }
            })
            .collect();
        let section_count = sections.len();
        let (section_entropies, overrun) = entropy_by_section(bytes, sections);

        let (import_names, import_count, export_count) = macho_symbols(macho, bytes);
        let suspicious_imports = find_suspicious_imports(import_names, bytes.len());

        let has_debug_info = macho
            .segments
            .iter()
            .any(|seg| seg.name().map(|n| n == "__DWARF").unwrap_or(false));

        let is_packed = overrun || section_entropies.iter().any(|&e| e > 7.0) || entropy > 7.0;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_strings_stop_at_the_score_cap() {
        let bytes: Vec<u8> = (0..10_000)
            .flat_map(|i| format!("cmd.exe /c job{i}\0").into_bytes())
            .collect();

        assert_eq!(
            extract_suspicious_strings(&bytes).len(),
            MAX_SUSPICIOUS_STRINGS
        );
    }

    #[test]
    fn section_entropy_is_bounded_and_fails_closed() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(1024).collect();

        let (halves, halves_overrun) = entropy_by_section(&bytes, [(0, 512), (512, 512)]);
        // Two whole-file decoys spend the budget ahead of the real section.
        let (_, decoys_overrun) = entropy_by_section(&bytes, [(0, 1024), (0, 1024), (512, 512)]);
        let (repeated, _) = entropy_by_section(&bytes, vec![(0, 1024); 1000]);

        assert!(halves.iter().all(|&e| e > 7.9));
        assert!(!halves_overrun);
        assert!(decoys_overrun);
        assert_eq!(repeated.iter().filter(|&&e| e > 0.0).count(), 2);
    }

    fn le_words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn macho_export_trie_cycle_is_not_walked() {
        // A 64-bit header and one LC_DYLD_EXPORTS_TRIE whose only node branches
        // back to itself. Walking it overflowed the stack and aborted the process.
        let mut bytes = le_words(&[0xfeed_facf, 0x0100_000c, 0, 2, 1, 16, 0, 0]);
        bytes.extend(le_words(&[0x8000_0033, 16, 48, 4]));
        bytes.extend([0x00, 0x01, 0x00, 0x00]);
        bytes.resize(64, 0);

        assert!(FileFeatures::extract_from_bytes(&bytes).is_ok());
    }

    #[test]
    fn macho_imports_and_exports_come_from_the_symbol_table() {
        let mut bytes = le_words(&[0xfeed_facf, 0x0100_000c, 0, 2, 1, 24, 0, 0]);
        // LC_SYMTAB: two nlist_64 entries at 64, string table at 96.
        bytes.extend(le_words(&[0x2, 24, 64, 2, 96, 17]));
        bytes.resize(64, 0);
        // _mprotect: undefined external, i.e. an import.
        bytes.extend(le_words(&[1]));
        bytes.extend([N_EXT | N_UNDF, 0, 0, 0]);
        bytes.extend([0; 8]);
        // _main: external defined in section 1, i.e. an export.
        bytes.extend(le_words(&[11]));
        bytes.extend([N_EXT | goblin::mach::symbols::N_SECT, 1, 0, 0]);
        bytes.extend(0x1000u64.to_le_bytes());
        bytes.extend(b"\0_mprotect\0_main\0");

        let features = FileFeatures::extract_from_bytes(&bytes).unwrap();

        assert_eq!((features.import_count, features.export_count), (1, 1));
        assert_eq!(features.suspicious_imports, ["_mprotect"]);
    }

    #[test]
    fn import_name_scans_stop_at_the_byte_budget() {
        let long = format!("{}mprotect", "x".repeat(1_000));

        let found = find_suspicious_imports(std::iter::repeat_n(long.as_str(), 1_000_000), 10_000);

        assert_eq!(found.len(), 9);
    }
}
