use addr2line::Loader;
use object::{
    BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionFlags, SectionKind, SymbolKind,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum rozyError {
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not a valid object file: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: object::Error,
    },
    #[error("{0} is not an ELF file")]
    NotElf(PathBuf),
    #[error("could not serialize report data: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Debug)]
pub struct AnalysisOptions {
    /// Resolve symbol addresses through DWARF line information.
    pub resolve_source: bool,
    /// Prefixes removed from source paths before grouping.
    pub strip_prefixes: Vec<PathBuf>,
    /// Optional display name. Defaults to the ELF file name.
    pub display_name: Option<String>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            resolve_source: true,
            strip_prefixes: Vec::new(),
            display_name: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryKind {
    Text,
    Data,
    Bss,
}

impl MemoryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Data => "data",
            Self::Bss => "bss",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemoryTotals {
    pub text: u64,
    pub data: u64,
    pub bss: u64,
    pub flash: u64,
    pub ram: u64,
}

impl MemoryTotals {
    fn add(&mut self, kind: MemoryKind, bytes: u64) {
        match kind {
            MemoryKind::Text => self.text += bytes,
            MemoryKind::Data => self.data += bytes,
            MemoryKind::Bss => self.bss += bytes,
        }
        self.flash = self.text + self.data;
        self.ram = self.data + self.bss;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionReport {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub memory: MemoryKind,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolReport {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub memory: MemoryKind,
    pub section: String,
    pub path: Vec<String>,
    /// Best-effort Rust crate attribution from DWARF paths or demangled symbols.
    pub crate_name: Option<String>,
    pub source: Option<String>,
    pub line: Option<u32>,
    pub synthetic: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    pub name: String,
    pub file: String,
    pub file_size: u64,
    pub architecture: String,
    pub endian: String,
    pub totals: MemoryTotals,
    pub sections: Vec<SectionReport>,
    pub symbols: Vec<SymbolReport>,
}

#[derive(Clone, Debug)]
struct RawSymbol {
    name: String,
    address: u64,
    declared_size: u64,
}

/// Analyze an ELF executable using its section table, symbol table, and DWARF
/// line information. Allocated section bytes are fully accounted for: gaps,
/// alignment, and stripped symbols become synthetic `<unattributed>` entries.
pub fn analyze_file(
    path: impl AsRef<Path>,
    options: &AnalysisOptions,
) -> Result<Analysis, rozyError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| rozyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let file = object::File::parse(&*bytes).map_err(|source| rozyError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    if file.format() != BinaryFormat::Elf {
        return Err(rozyError::NotElf(path.to_path_buf()));
    }

    let architecture = format!("{:?}", file.architecture());
    let clear_thumb_bit = architecture == "Arm";
    let loader = if options.resolve_source {
        Loader::new(path).ok()
    } else {
        None
    };

    let mut totals = MemoryTotals::default();
    let mut sections = Vec::new();
    let mut section_meta = HashMap::<usize, (String, u64, u64, MemoryKind)>::new();

    for section in file.sections() {
        if !is_allocated(&section) || section.size() == 0 {
            continue;
        }
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let memory = classify_section(
            &name,
            section.kind(),
            has_elf_flag(&section, object::elf::SHF_EXECINSTR.into()),
            has_elf_flag(&section, object::elf::SHF_WRITE.into()),
        );
        totals.add(memory, section.size());
        section_meta.insert(
            section.index().0,
            (name.clone(), section.address(), section.size(), memory),
        );
        sections.push(SectionReport {
            name,
            address: section.address(),
            size: section.size(),
            memory,
            kind: format!("{:?}", section.kind()),
        });
    }

    let mut by_section = HashMap::<usize, Vec<RawSymbol>>::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if !symbol.is_definition()
            || symbol.is_undefined()
            || matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File)
        {
            continue;
        }
        let Some(section_index) = symbol.section_index().map(|index| index.0) else {
            continue;
        };
        if !section_meta.contains_key(&section_index) {
            continue;
        }
        let Ok(raw_name) = symbol.name() else {
            continue;
        };
        if raw_name.is_empty() {
            continue;
        }
        let address = if clear_thumb_bit {
            symbol.address() & !1
        } else {
            symbol.address()
        };
        by_section
            .entry(section_index)
            .or_default()
            .push(RawSymbol {
                name: addr2line::demangle_auto(raw_name.into(), None).into_owned(),
                address,
                declared_size: symbol.size(),
            });
    }

    let mut symbols = Vec::new();
    for (index, (section_name, section_start, section_size, memory)) in &section_meta {
        let section_end = section_start.saturating_add(*section_size);
        let mut addresses = BTreeMap::<u64, Vec<RawSymbol>>::new();
        for symbol in by_section.remove(index).unwrap_or_default() {
            if symbol.address >= *section_start && symbol.address < section_end {
                addresses.entry(symbol.address).or_default().push(symbol);
            }
        }

        let starts: Vec<u64> = addresses.keys().copied().collect();
        let mut cursor = *section_start;
        for (position, start) in starts.iter().copied().enumerate() {
            if start > cursor {
                push_synthetic(&mut symbols, section_name, *memory, cursor, start - cursor);
            }
            let aliases = &addresses[&start];
            let symbol = choose_symbol(aliases);
            let next = starts.get(position + 1).copied().unwrap_or(section_end);
            let declared_end = if symbol.declared_size == 0 {
                next
            } else {
                start.saturating_add(symbol.declared_size).min(section_end)
            };
            let end = declared_end.min(next).max(start);
            let effective_start = start.max(cursor);
            if end > effective_start {
                let probe = effective_start;
                let (source, line) = source_location(loader.as_ref(), probe);
                let grouped_path = source
                    .as_deref()
                    .map(|source| normalize_source_path(source, &options.strip_prefixes))
                    .unwrap_or_else(|| vec!["[sections]".into(), section_name.clone()]);
                let crate_name = infer_crate_name(&symbol.name, &grouped_path);
                symbols.push(SymbolReport {
                    name: symbol.name.clone(),
                    address: effective_start,
                    size: end - effective_start,
                    memory: *memory,
                    section: section_name.clone(),
                    path: grouped_path,
                    crate_name,
                    source,
                    line,
                    synthetic: false,
                });
                cursor = end;
            }
        }
        if cursor < section_end {
            push_synthetic(
                &mut symbols,
                section_name,
                *memory,
                cursor,
                section_end - cursor,
            );
        }
    }

    sections.sort_by_key(|section| section.address);
    symbols.sort_by_key(|symbol| (symbol.memory.as_str(), symbol.address));
    let display_name = options.display_name.clone().unwrap_or_else(|| {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ELF report")
            .to_string()
    });

    Ok(Analysis {
        name: display_name,
        file: path.display().to_string(),
        file_size: bytes.len() as u64,
        architecture,
        endian: if file.is_little_endian() {
            "little".into()
        } else {
            "big".into()
        },
        totals,
        sections,
        symbols,
    })
}

fn is_allocated<'data, S: ObjectSection<'data>>(section: &S) -> bool {
    match section.flags() {
        SectionFlags::Elf { sh_flags } => sh_flags & u64::from(object::elf::SHF_ALLOC) != 0,
        _ => matches!(
            section.kind(),
            SectionKind::Text
                | SectionKind::Data
                | SectionKind::ReadOnlyData
                | SectionKind::ReadOnlyString
                | SectionKind::UninitializedData
                | SectionKind::Common
                | SectionKind::Tls
                | SectionKind::UninitializedTls
        ),
    }
}

fn has_elf_flag<'data, S: ObjectSection<'data>>(section: &S, flag: u64) -> bool {
    matches!(section.flags(), SectionFlags::Elf { sh_flags } if sh_flags & flag != 0)
}

fn classify_section(name: &str, kind: SectionKind, executable: bool, writable: bool) -> MemoryKind {
    let lower = name.to_ascii_lowercase();
    if executable || kind == SectionKind::Text {
        MemoryKind::Text
    } else if kind.is_bss()
        || lower == ".bss"
        || lower.starts_with(".bss.")
        || lower.contains("stack")
        || lower == ".noinit"
    {
        MemoryKind::Bss
    } else if writable
        || matches!(kind, SectionKind::Data | SectionKind::Tls)
        || lower == ".data"
        || lower.starts_with(".data.")
        || lower == ".relocate"
    {
        MemoryKind::Data
    } else {
        MemoryKind::Text
    }
}

fn choose_symbol(symbols: &[RawSymbol]) -> &RawSymbol {
    symbols
        .iter()
        .max_by_key(|symbol| {
            (
                symbol.declared_size,
                !symbol.name.starts_with('.'),
                std::cmp::Reverse(symbol.name.len()),
            )
        })
        .expect("an address group always contains a symbol")
}

fn source_location(loader: Option<&Loader>, address: u64) -> (Option<String>, Option<u32>) {
    let Some(loader) = loader else {
        return (None, None);
    };
    match loader.find_location(address) {
        Ok(Some(location)) => (location.file.map(str::to_string), location.line),
        _ => (None, None),
    }
}

fn push_synthetic(
    symbols: &mut Vec<SymbolReport>,
    section: &str,
    memory: MemoryKind,
    address: u64,
    size: u64,
) {
    if size == 0 {
        return;
    }
    symbols.push(SymbolReport {
        name: "<unattributed>".into(),
        address,
        size,
        memory,
        section: section.into(),
        path: vec!["[sections]".into(), section.into()],
        crate_name: None,
        source: None,
        line: None,
        synthetic: true,
    });
}

fn normalize_source_path(source: &str, strip_prefixes: &[PathBuf]) -> Vec<String> {
    let normalized = source.replace('\\', "/");
    let path = Path::new(&normalized);
    let stripped = strip_prefixes
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix).ok())
        .unwrap_or(path);
    let mut parts: Vec<String> = stripped
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str().map(str::to_string),
            _ => None,
        })
        .collect();

    if let Some(riot) = parts.iter().rposition(|part| part == "RIOT") {
        parts = parts.split_off(riot + 1);
    } else if let Some(registry) = parts.iter().position(|part| part == "registry") {
        if parts.get(registry + 1).is_some_and(|part| part == "src") {
            let crate_index = (registry + 3).min(parts.len());
            let mut compact = vec!["cargo-registry".to_string()];
            compact.extend(parts[crate_index..].iter().cloned());
            parts = compact;
        }
    } else if let Some(src) = parts.iter().rposition(|part| part == "src") {
        if src > 0 {
            parts = parts.split_off(src - 1);
        }
    }

    if parts.len() > 7 {
        parts = parts.split_off(parts.len() - 7);
    }
    if parts.is_empty() {
        vec!["[source]".into()]
    } else {
        parts
    }
}

fn infer_crate_name(symbol: &str, path: &[String]) -> Option<String> {
    if path.first().is_some_and(|part| part == "cargo-registry") {
        if let Some(versioned) = path.get(1) {
            if let Some(name) = strip_crate_version(versioned) {
                return Some(name.to_string());
            }
        }
    }

    if let Some(src) = path.iter().rposition(|part| part == "src") {
        if let Some(name) = src.checked_sub(1).and_then(|index| path.get(index)) {
            if valid_crate_name(name) {
                return Some(name.clone());
            }
        }
    }

    if !symbol.contains("::") {
        return None;
    }
    let namespace = symbol
        .trim_start_matches('<')
        .split("::")
        .next()
        .unwrap_or_default()
        .trim();
    valid_crate_name(namespace).then(|| namespace.to_string())
}

fn strip_crate_version(value: &str) -> Option<&str> {
    value.match_indices('-').rev().find_map(|(dash, _)| {
        let suffix = &value[dash + 1..];
        let starts_with_digit = suffix.chars().next().is_some_and(|ch| ch.is_ascii_digit());
        (dash > 0 && starts_with_digit).then_some(&value[..dash])
    })
}

fn valid_crate_name(value: &str) -> bool {
    !value.is_empty()
        && value != "[sections]"
        && value.chars().next().is_some_and(|ch| ch.is_alphabetic() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_follow_embedded_size_semantics() {
        let mut totals = MemoryTotals::default();
        totals.add(MemoryKind::Text, 100);
        totals.add(MemoryKind::Data, 20);
        totals.add(MemoryKind::Bss, 30);
        assert_eq!(totals.flash, 120);
        assert_eq!(totals.ram, 50);
    }

    #[test]
    fn compacts_cargo_registry_paths() {
        let path = normalize_source_path(
            "/home/u/.cargo/registry/src/index/hashbrown-0.15.0/src/map.rs",
            &[],
        );
        assert_eq!(path[0], "cargo-registry");
        assert!(path.iter().any(|part| part == "hashbrown-0.15.0"));
    }

    #[test]
    fn attributes_registry_crates_without_the_version() {
        assert_eq!(
            infer_crate_name(
                "hashbrown::map::HashMap::get",
                &[
                    "cargo-registry".into(),
                    "hashbrown-0.15.0".into(),
                    "src".into(),
                    "map.rs".into(),
                ],
            ),
            Some("hashbrown".into())
        );
        assert_eq!(
            strip_crate_version("embedded-hal-1.0.0"),
            Some("embedded-hal")
        );
    }

    #[test]
    fn attributes_local_and_symbol_only_crates() {
        assert_eq!(
            infer_crate_name(
                "rozy::main",
                &["rozy".into(), "src".into(), "main.rs".into()]
            ),
            Some("rozy".into())
        );
        assert_eq!(
            infer_crate_name(
                "std::rt::lang_start",
                &["[sections]".into(), ".text".into()]
            ),
            Some("std".into())
        );
        assert_eq!(
            infer_crate_name("<alloc::vec::Vec<T> as core::fmt::Debug>::fmt", &[]),
            Some("alloc".into())
        );
    }
}
