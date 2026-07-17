use rozy::{analyze_file, write_html, AnalysisOptions, MemoryTotals, rozyError};
use clap::Parser;
use serde_json::Value;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

#[derive(Debug, Parser)]
#[command(
    name = "cargo rozy",
    version,
    about = "Analyze an ELF and generate an interactive, self-contained size report",
    after_help = "Examples:\n  cargo rozy firmware.elf --open\n  cargo rozy --release --bin firmware\n  cargo rozy --target thumbv7em-none-eabihf --release"
)]
struct Cli {
    /// Existing ELF file. If omitted, cargo-rozy builds the current package.
    elf: Option<PathBuf>,

    /// Output HTML report.
    #[arg(short, long, default_value = "rozy-report.html")]
    output: PathBuf,

    /// Also write the raw analysis as JSON.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Open the generated report in the default browser.
    #[arg(long)]
    open: bool,

    /// Skip DWARF source-path resolution.
    #[arg(long)]
    no_source: bool,

    /// Remove a prefix from source paths (repeatable).
    #[arg(long, value_name = "PATH")]
    strip_prefix: Vec<PathBuf>,

    /// Display name used in the report.
    #[arg(long)]
    name: Option<String>,

    /// Analyze this binary target when building a Cargo project.
    #[arg(long, conflicts_with = "example")]
    bin: Option<String>,

    /// Analyze this example target when building a Cargo project.
    #[arg(long, conflicts_with = "bin")]
    example: Option<String>,

    /// Build with Cargo's release profile.
    #[arg(long, conflicts_with = "profile")]
    release: bool,

    /// Cargo build profile.
    #[arg(long)]
    profile: Option<String>,

    /// Cargo target triple.
    #[arg(long)]
    target: Option<String>,

    /// Cargo package in a workspace.
    #[arg(short = 'p', long)]
    package: Option<String>,

    /// Path to Cargo.toml.
    #[arg(long)]
    manifest_path: Option<PathBuf>,

    /// Comma-separated Cargo features.
    #[arg(long)]
    features: Option<String>,

    /// Activate all Cargo features.
    #[arg(long)]
    all_features: bool,

    /// Do not activate default Cargo features.
    #[arg(long)]
    no_default_features: bool,

    /// Suppress the summary table.
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<OsString> = env::args_os().collect();
    if args.get(1).is_some_and(|arg| arg == OsStr::new("rozy")) {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);
    let elf = match cli.elf.as_deref() {
        Some(path) => path.to_path_buf(),
        None => build_and_find_elf(&cli)?,
    };

    let options = AnalysisOptions {
        resolve_source: !cli.no_source,
        strip_prefixes: cli.strip_prefix.clone(),
        display_name: cli.name.clone(),
    };
    let analysis = analyze_file(&elf, &options)?;
    write_html(&cli.output, &analysis)?;
    if let Some(json) = &cli.json {
        let rendered = serde_json::to_string_pretty(&analysis)?;
        fs::write(json, rendered).map_err(|source| rozyError::Write {
            path: json.clone(),
            source,
        })?;
    }

    if !cli.quiet {
        print_summary(&analysis.name, &analysis.totals, &cli.output);
    }
    if cli.open {
        open_report(&cli.output)?;
    }
    Ok(())
}

fn build_and_find_elf(cli: &Cli) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command
        .arg("build")
        .arg("--message-format=json-render-diagnostics");
    if cli.release {
        command.arg("--release");
    }
    push_option(&mut command, "--profile", cli.profile.as_deref());
    push_option(&mut command, "--target", cli.target.as_deref());
    push_option(&mut command, "--package", cli.package.as_deref());
    if let Some(path) = &cli.manifest_path {
        command.arg("--manifest-path").arg(path);
    }
    push_option(&mut command, "--bin", cli.bin.as_deref());
    push_option(&mut command, "--example", cli.example.as_deref());
    push_option(&mut command, "--features", cli.features.as_deref());
    if cli.all_features {
        command.arg("--all-features");
    }
    if cli.no_default_features {
        command.arg("--no-default-features");
    }
    command.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("cargo build failed with {}", output.status).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut artifacts = Vec::<(String, PathBuf)>::new();
    for line in stdout.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["executable"].is_null() {
            continue;
        }
        let Some(path) = message["executable"].as_str() else {
            continue;
        };
        let kinds = message["target"]["kind"].as_array();
        let accepted = kinds.is_some_and(|kinds| {
            kinds.iter().any(|kind| {
                kind.as_str() == Some("bin")
                    || (cli.example.is_some() && kind.as_str() == Some("example"))
            })
        });
        if accepted {
            artifacts.push((
                message["target"]["name"]
                    .as_str()
                    .unwrap_or("unnamed")
                    .to_string(),
                PathBuf::from(path),
            ));
        }
    }
    artifacts.sort();
    artifacts.dedup_by(|left, right| left.1 == right.1);
    match artifacts.as_slice() {
        [(_, path)] => Ok(path.clone()),
        [] => Err(
            "cargo produced no executable ELF artifact; select one with --bin or --example".into(),
        ),
        many => {
            let names = many
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(
                format!("cargo produced multiple executables ({names}); select one with --bin")
                    .into(),
            )
        }
    }
}

fn push_option(command: &mut Command, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        command.arg(flag).arg(value);
    }
}

fn print_summary(name: &str, totals: &MemoryTotals, output: &Path) {
    println!("\n{name}");
    println!("{:<12} {:>12}", "region", "bytes");
    println!("{:-<25}", "");
    println!("{:<12} {:>12}", "text", totals.text);
    println!("{:<12} {:>12}", "data", totals.data);
    println!("{:<12} {:>12}", "bss", totals.bss);
    println!("{:<12} {:>12}", "flash", totals.flash);
    println!("{:<12} {:>12}", "ram", totals.ram);
    println!("\nReport: {}", output.display());
}

fn open_report(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let absolute = path.canonicalize()?;
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("start").arg("").arg(&absolute);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(&absolute);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(&absolute);
        command
    };
    command.spawn()?;
    Ok(())
}
