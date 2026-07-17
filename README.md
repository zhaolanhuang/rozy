# Rosy

> Vibe coded by GPT-5.6 Sol, with few wetware interventions. ;)

`rosy` turns an ELF executable into an interactive, self-contained size
report. It is a Rust re-imagining of [RIOT-OS/cosy](https://github.com/RIOT-OS/cosy),
with direct ELF/DWARF parsing and first-class Cargo integration.

The generated HTML works offline and contains the sunburst, searchable symbol
table, source/crate/section grouping, Text/Data/BSS filters, and JSON/CSV exports.

## Why another size tool?

- No Python, GNU `nm`, GNU `size`, linker map, or local web server is required.
- ELF sections are the source of truth, so Flash and runtime RAM totals remain
  correct even when symbols are stripped or alignment bytes are present.
- DWARF paths group symbols by crate, source directory, RIOT subsystem, or ELF
  section.
- The report can switch to a crate-first hierarchy. 
- The analyzer is also exposed as a Rust library.

## Install

```sh
cargo install rosy
```

## Use

Analyze an existing embedded ELF:

```sh
cargo rosy path/to/firmware.elf --open
```

Build and analyze the current Cargo binary:

```sh
cargo rosy --release --bin firmware --open
```

Cross-compile first, then analyze the executable reported by Cargo:

```sh
cargo rosy --target thumbv7em-none-eabihf --release --bin firmware
```

Useful options:

```text
--json analysis.json       also save the machine-readable model
--no-source                skip DWARF source lookup
--strip-prefix PATH        remove a build-machine path prefix (repeatable)
--example NAME             build and analyze a Cargo example
--manifest-path PATH       use a specific Cargo.toml
--features FEATURES        forward Cargo features
```

For good source attribution, keep DWARF line information in the ELF passed to
the analyzer. The deployed/stripped image can remain unchanged.

## Library API

```rust,no_run
use rosy::{analyze_file, write_html, AnalysisOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = analyze_file("firmware.elf", &AnalysisOptions::default())?;
    write_html("size-report.html", &analysis)?;
    Ok(())
}
```

## Size accounting

The report follows embedded `size` semantics:

```text
Flash = text + initialized data
RAM   = initialized data + bss/noinit/stacks
```

Every allocated section byte is represented. Areas not covered by a usable
symbol are emitted as `<unattributed>`; this includes alignment, linker padding,
and stripped/zero-sized symbols that cannot be safely inferred.

## Relationship to RIOT-OS/cosy

The original cosy requires an ELF plus linker map, combines `nm` source lines
with map-file symbol sizes, then serves a D3 sunburst. `rosy` preserves
the useful Text/Data/BSS and hierarchical exploration model while using an
independent Rust implementation and a dependency-free report frontend.

