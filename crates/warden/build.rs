//! Build-time construction of the `warden-ebpf` Tier-2 aya BPF-LSM object.
//!
//! Ported from mirage2web's `mirage-secd/build.rs` with names adapted
//! (`SECD_BUILD_EBPF` → `ML_WARDEN_BUILD_EBPF`, `secd-ebpf` → `warden-ebpf`,
//! `secd-tier2` → `mlc-warden-tier2`).
//!
//! # `warden-ebpf` object
//!
//! `warden-ebpf/` compiles to `bpfel-unknown-none` via nightly + `-Z
//! build-std=core` + `bpf-linker` (LLVM 19) — a toolchain this crate's own
//! `cargo check`/normal `cargo build` on stable/Windows CANNOT run.
//! `aya_build::build_ebpf` itself already gates on the `AYA_BUILD_SKIP` env
//! var (skip if `1`/`true`) — but its OWN default, if that var is unset, is
//! to ATTEMPT the nightly build, which would break every normal dev/CI
//! `cargo check` on this crate. This build.rs therefore inverts the polarity
//! at ITS OWN level: real Tier-2 compilation is OPT-IN via
//! `ML_WARDEN_BUILD_EBPF=1` (set only by the linux Docker Tier-2 build
//! stage); by default (unset, every normal dev/CI build) this writes an
//! EMPTY placeholder object to `$OUT_DIR/mlc-warden-tier2` and never invokes
//! `aya_build::build_ebpf` at all — `bpf_lsm::loader::load_and_pin` (Linux
//! userspace side) detects the empty object at RUNTIME and returns a
//! graceful `Err` (never a panic, never a build failure) — see that module's
//! doc.
//!
//! UNVALIDATED on this authoring dev box (Windows, no nightly/rust-src/
//! bpf-linker/LLVM19): the `ML_WARDEN_BUILD_EBPF=1` real-build path is
//! exercised only in the linux Docker build stage.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Opt-in gate for the REAL `warden-ebpf` nightly build (linux Docker stage
/// only — see module doc). Any value other than `1`/`true`
/// (case-insensitive), or unset, leaves the eBPF build skipped.
const ML_WARDEN_BUILD_EBPF_ENV: &str = "ML_WARDEN_BUILD_EBPF";

/// The `[[bin]] name` in `warden-ebpf/Cargo.toml` — also the filename
/// `aya-build::build_ebpf` copies its compiled artifact to under `OUT_DIR`,
/// and the exact string `bpf_lsm::loader`'s
/// `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mlc-warden-tier2"))`
/// expects.
const WARDEN_EBPF_BIN_NAME: &str = "mlc-warden-tier2";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={ML_WARDEN_BUILD_EBPF_ENV}");

    // The Tier-2 eBPF object is built by `build_warden_ebpf` (aya-build
    // shells out to `cargo build -p warden-ebpf`). cargo does NOT track that
    // INNER build's sources as inputs of THIS build script, so without these
    // directives an edit to a `warden-ebpf` source file does NOT re-run the
    // build script — cargo re-embeds the previously-built eBPF object from
    // its cache and the source edit silently never ships. (Mirage's
    // masked-vs-full cgroup-id fix shipped stale exactly once for this
    // reason.) Declare the whole eBPF crate as an input so any change to it
    // re-triggers the object rebuild.
    println!("cargo:rerun-if-changed=warden-ebpf/src");
    println!("cargo:rerun-if-changed=warden-ebpf/Cargo.toml");

    build_warden_ebpf();
}

/// Build the real `warden-ebpf` Tier-2 object ONLY when
/// `ML_WARDEN_BUILD_EBPF=1` (linux Docker stage). Otherwise write an empty
/// placeholder so `include_bytes_aligned!` in `bpf_lsm::loader` still has a
/// file to embed (an empty slice, which that module's runtime load path
/// detects and gracefully degrades on — see its doc).
fn build_warden_ebpf() {
    let out_path = out_dir().join(WARDEN_EBPF_BIN_NAME);

    if !ml_warden_build_ebpf_requested() {
        fs::write(&out_path, []).unwrap_or_else(|e| {
            panic!("write empty warden-ebpf placeholder to {}: {e}", out_path.display());
        });
        println!(
            "cargo:warning=[mlc-warden/build] {ML_WARDEN_BUILD_EBPF_ENV} not set — warden-ebpf \
             Tier-2 object is an EMPTY placeholder this build (expected for every normal dev/CI \
             cargo build; real Tier-2 compilation only happens in the linux Docker build stage)"
        );
        return;
    }

    // Real build path — delegates to aya-build, which itself shells out to
    // `cargo +nightly build --target bpfel-unknown-none -Z build-std=core`
    // (via rustup, or the current toolchain if rustup is unavailable) and
    // requires `bpf-linker` on PATH.
    //
    // `warden-ebpf` is DELIBERATELY not a member of the `mylittlechart-server`
    // workspace (its own `[workspace]` table + nightly `-Z build-std`
    // requirement is incompatible with this crate's stable-rustc workspace —
    // see `warden-ebpf/Cargo.toml` doc) — so `cargo_metadata` must be pointed
    // explicitly at ITS manifest, not resolved via ambient workspace
    // discovery.
    let ebpf_manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("warden-ebpf")
        .join("Cargo.toml");

    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(&ebpf_manifest_path)
        .no_deps()
        .exec()
        .unwrap_or_else(|e| {
            panic!(
                "cargo_metadata::MetadataCommand::exec against {}: {e}",
                ebpf_manifest_path.display()
            )
        });

    let ebpf_package = metadata
        .packages
        .into_iter()
        .find(|p| p.name.as_str() == "warden-ebpf")
        .expect("warden-ebpf package not found — check warden-ebpf/Cargo.toml [package] name");

    let root_dir = ebpf_package
        .manifest_path
        .parent()
        .expect("warden-ebpf manifest_path has no parent directory")
        .to_string();

    let package = aya_build::Package {
        name: ebpf_package.name.as_str(),
        root_dir: root_dir.as_str(),
        ..Default::default()
    };

    // `aya_build::build_ebpf` shells out to plain `cargo build --package
    // warden-ebpf ...` with NO `--manifest-path` — it relies entirely on
    // ambient workspace discovery from the current working directory. Since
    // `warden-ebpf` is its own standalone workspace (not a member of
    // `mylittlechart-server`), the current directory must actually BE inside
    // `warden-ebpf/`'s own workspace for that ambient discovery to find it —
    // temporarily `chdir` there for the duration of this call, then restore.
    let original_cwd = env::current_dir().expect("current_dir readable at build-script start");
    env::set_current_dir(&root_dir)
        .unwrap_or_else(|e| panic!("chdir to warden-ebpf root {root_dir}: {e}"));

    let build_result = aya_build::build_ebpf([package], aya_build::Toolchain::default());

    env::set_current_dir(&original_cwd)
        .unwrap_or_else(|e| panic!("chdir back to {}: {e}", original_cwd.display()));

    build_result
        .expect("aya_build::build_ebpf failed — see cargo:warning output above for the underlying error");

    println!("cargo:warning=[mlc-warden/build] warden-ebpf Tier-2 object built via ML_WARDEN_BUILD_EBPF=1");
}

fn ml_warden_build_ebpf_requested() -> bool {
    match env::var(ML_WARDEN_BUILD_EBPF_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true"
        }
        Err(_) => false,
    }
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"))
}
