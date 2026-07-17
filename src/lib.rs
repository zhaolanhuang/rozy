//! ELF size analysis and self-contained HTML visualization.
//!
//! `rosy` is inspired by RIOT-OS/cosy, but parses ELF files directly and
//! does not require GNU `nm`, `size`, a linker map, Python, or a web server.

mod analyze;
mod report;

pub use analyze::{
    analyze_file, Analysis, AnalysisOptions, MemoryKind, MemoryTotals, RosyError, SectionReport,
    SymbolReport,
};
pub use report::{render_html, write_html};
