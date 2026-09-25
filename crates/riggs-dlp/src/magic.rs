use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SensitiveFileType {
    Pptx,
    Xlsx,
    Docx,
    Ppt,
    Xls,
    Doc,
    Pdf,
    Csv,
    SourceCode,
    PrivateKey,
    DatabaseDump,
}

impl std::fmt::Display for SensitiveFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pptx => write!(f, "pptx"),
            Self::Xlsx => write!(f, "xlsx"),
            Self::Docx => write!(f, "docx"),
            Self::Ppt => write!(f, "ppt"),
            Self::Xls => write!(f, "xls"),
            Self::Doc => write!(f, "doc"),
            Self::Pdf => write!(f, "pdf"),
            Self::Csv => write!(f, "csv"),
            Self::SourceCode => write!(f, "source_code"),
            Self::PrivateKey => write!(f, "private_key"),
            Self::DatabaseDump => write!(f, "database_dump"),
        }
    }
}

impl SensitiveFileType {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().as_str() {
            "pptx" => Some(Self::Pptx),
            "xlsx" => Some(Self::Xlsx),
            "docx" => Some(Self::Docx),
            "ppt" => Some(Self::Ppt),
            "xls" => Some(Self::Xls),
            "doc" => Some(Self::Doc),
            "pdf" => Some(Self::Pdf),
            "csv" => Some(Self::Csv),
            "rs" | "py" | "go" | "js" | "ts" | "java" | "c" | "cpp" | "h" | "rb" | "ex" | "exs" => {
                Some(Self::SourceCode)
            }
            "pem" | "key" | "p12" | "pfx" => Some(Self::PrivateKey),
            "sql" | "sqlite" | "db" | "sqlite3" => Some(Self::DatabaseDump),
            _ => None,
        }
    }
}

const OOXML_MAGIC: &[u8] = &[0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0];
const PDF_MAGIC: &[u8] = b"%PDF";
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const PEM_MAGIC: &[u8] = b"-----BEGIN";

pub fn detect_from_magic(header: &[u8]) -> Option<SensitiveFileType> {
    if header.len() < 4 {
        return None;
    }

    if header.starts_with(OOXML_MAGIC) {
        // OOXML container — could be pptx, xlsx, or docx.
        // Without reading the ZIP central directory we can't distinguish,
        // so return the most conservative match.
        return Some(SensitiveFileType::Docx);
    }

    if header.starts_with(OLE2_MAGIC) {
        return Some(SensitiveFileType::Doc);
    }

    if header.starts_with(PDF_MAGIC) {
        return Some(SensitiveFileType::Pdf);
    }

    if header.len() >= 16 && header.starts_with(SQLITE_MAGIC) {
        return Some(SensitiveFileType::DatabaseDump);
    }

    if header.starts_with(PEM_MAGIC) {
        return Some(SensitiveFileType::PrivateKey);
    }

    None
}

pub fn detect_file_type(path: &Path, header: Option<&[u8]>) -> Option<SensitiveFileType> {
    // Magic bytes take priority (defeats extension renaming)
    if let Some(hdr) = header {
        if let Some(ft) = detect_from_magic(hdr) {
            return Some(ft);
        }
    }

    // Fall back to extension
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(SensitiveFileType::from_extension)
}

pub async fn read_file_header(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    let mut file = File::open(path).await.ok()?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).await.ok()?;
    buf.truncate(n);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_detection() {
        assert_eq!(
            SensitiveFileType::from_extension("pptx"),
            Some(SensitiveFileType::Pptx)
        );
        assert_eq!(
            SensitiveFileType::from_extension("XLSX"),
            Some(SensitiveFileType::Xlsx)
        );
        assert_eq!(
            SensitiveFileType::from_extension("pdf"),
            Some(SensitiveFileType::Pdf)
        );
        assert_eq!(SensitiveFileType::from_extension("mp3"), None);
    }

    #[test]
    fn magic_byte_detection() {
        assert_eq!(
            detect_from_magic(&[0x50, 0x4B, 0x03, 0x04, 0x00]),
            Some(SensitiveFileType::Docx)
        );
        assert_eq!(
            detect_from_magic(&[0xD0, 0xCF, 0x11, 0xE0, 0x00]),
            Some(SensitiveFileType::Doc)
        );
        assert_eq!(detect_from_magic(b"%PDF-1.7"), Some(SensitiveFileType::Pdf));
        assert_eq!(detect_from_magic(b"\x00\x00"), None);
    }

    #[test]
    fn magic_takes_priority_over_extension() {
        let path = Path::new("/tmp/renamed.txt");
        let header = &[0x50, 0x4B, 0x03, 0x04];
        assert_eq!(
            detect_file_type(path, Some(header)),
            Some(SensitiveFileType::Docx)
        );
    }
}
