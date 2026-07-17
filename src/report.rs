use crate::{Analysis, rozyError};
use std::fs;
use std::path::Path;

const TEMPLATE: &str = include_str!("report.html");

/// Render an analysis as a self-contained, offline HTML report.
pub fn render_html(analysis: &Analysis) -> Result<String, rozyError> {
    let json = serde_json::to_string(analysis)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e");
    Ok(TEMPLATE.replace("__rozy_REPORT_JSON__", &json))
}

/// Render and write an analysis as a self-contained, offline HTML report.
pub fn write_html(path: impl AsRef<Path>, analysis: &Analysis) -> Result<(), rozyError> {
    let path = path.as_ref();
    fs::write(path, render_html(analysis)?).map_err(|source| rozyError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryKind, MemoryTotals, SymbolReport};

    #[test]
    fn embeds_json_without_closing_script() {
        let analysis = Analysis {
            name: "</script>".into(),
            file: "x.elf".into(),
            file_size: 0,
            architecture: "Arm".into(),
            endian: "little".into(),
            totals: MemoryTotals::default(),
            sections: vec![],
            symbols: vec![],
        };
        let html = render_html(&analysis).unwrap();
        assert!(!html.contains("const REPORT = {\"name\":\"</script>"));
    }

    #[test]
    fn embeds_crate_grouping_and_attribution() {
        let analysis = Analysis {
            name: "firmware".into(),
            file: "firmware.elf".into(),
            file_size: 1,
            architecture: "Arm".into(),
            endian: "little".into(),
            totals: MemoryTotals::default(),
            sections: vec![],
            symbols: vec![SymbolReport {
                name: "rozy::main".into(),
                address: 0,
                size: 1,
                memory: MemoryKind::Text,
                section: ".text".into(),
                path: vec!["rozy".into(), "src".into(), "main.rs".into()],
                crate_name: Some("rozy".into()),
                source: Some("rozy/src/main.rs".into()),
                line: Some(1),
                synthetic: false,
            }],
        };
        let html = render_html(&analysis).unwrap();
        assert!(html.contains("<option value=\"crate\">Rust crates</option>"));
        assert!(html.contains("\"crate_name\":\"rozy\""));
        assert!(html.contains("id=\"tableTotal\""));
        assert!(html.contains("list.reduce((sum,s)=>sum+s.size,0)"));
        assert!(html.contains("for(const s of list)"));
        assert!(!html.contains("list.slice(0,250)"));
    }
}
