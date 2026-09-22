//! `/api/release/publish` — the only place a release artifact is copied
//! anywhere. 2026-08-30 redesign: the control box stores no artifacts at
//! all — the bytes live only on the public edges (served by nginx from
//! `/opt/mlc/static/dl/`), and the control box holds just the manifest row.
//!
//! Control flow:
//!   1. Validate the local artifact (exists, not suspiciously small — see
//!      `deploy::validate_artifact_size`; unlike `deploy`, a `.exe` is
//!      expected here, not rejected).
//!   2. Compute the local sha256.
//!   3. For EVERY edge: `mkdir -p` the target dir, atomic SFTP upload at
//!      mode 0644 (see `ssh::upload` — `.new` + verified size + chmod +
//!      rename, so a reader on the edge never sees a partial or
//!      wrong-mode file — a `403` cached by Cloudflare for a year is exactly
//!      the failure a wrong mode produces), then sha256-verify on the edge.
//!   4. Any edge failing upload or verification aborts the whole publish —
//!      and unwinds whatever DID land on the other edges. A manifest row is
//!      registered ONLY after every edge is confirmed, and a half-uploaded
//!      release must not linger on the edges it did reach either.
//!   5. Only once every edge has verified: register the manifest row on the
//!      control box (`register_release`). Since the 2026-09-22
//!      admin-listener split (`docs/mlc/audits/api-surface-hardening-2026-09-10.md`
//!      §3/§6), the admin API is its own loopback-only listener, unreachable
//!      from off-box entirely — so this still runs `curl` from inside a box
//!      ssh session (same indirection `deploy::health_cmd` / `ops::unlock`
//!      use), but against `$A` (`state::APP_ADMIN_RESOLVE`, fixed
//!      `127.0.0.1` host, `ADMIN_PORT` read back from the unit — see its own
//!      doc for why the port still needs remote resolution even though the
//!      host does not), not the main app port `$H`
//!      ([`crate::state::APP_HEALTH_RESOLVE`]) resolves.
//!
//! Command/parsing helpers are pure and unit-tested without a box or edge;
//! [`publish`] is the async orchestrator over `crate::ssh`.

use std::path::Path;
use std::sync::Arc;

use rand::RngCore;
use serde::Serialize;

use crate::deploy;
use crate::error::OpsdError;
use crate::ops;
use crate::state::{EdgeConfig, OpsdState};

/// Root nginx serves release artifacts from on each edge — see
/// `updates::download_binary`'s `/dl/{platform}/{version}/{filename}`
/// redirect target on the mylittlechart-server side.
const EDGE_STATIC_DL_ROOT: &str = "/opt/mlc/static/dl";

#[derive(Debug, Serialize)]
pub struct PublishOutcome {
    pub ok: bool,
    pub sha256: String,
    pub size: u64,
    pub filename: String,
    pub steps: Vec<String>,
}

/// What the operator asked to publish. Grouped into one struct (rather than
/// threading each field through [`publish`] individually) so the function
/// signature stays readable as fields get added.
pub struct PublishRequest<'a> {
    pub local: &'a Path,
    pub platform: &'a str,
    pub version: &'a str,
    pub channel: &'a str,
    pub release_notes: &'a str,
    pub signature: &'a str,
}

/// The manifest fields [`register_release`] sends to the control box —
/// separated from [`PublishRequest`] because it additionally carries the
/// filename and sha256 that only exist after the edge uploads succeed.
struct ReleaseMeta<'a> {
    platform: &'a str,
    version: &'a str,
    channel: &'a str,
    filename: &'a str,
    sha256: &'a str,
    file_size: u64,
    release_notes: &'a str,
    signature: &'a str,
}

/// Validate the operator-supplied local artifact path for a release publish.
/// Shares `deploy`'s existence/size checks but deliberately does NOT share
/// its `.exe` rejection — a win64 release artifact IS an `.exe`, and that
/// check is specific to the linux server binary `deploy` ships.
pub fn validate_local_artifact(path: &Path) -> Result<u64, OpsdError> {
    deploy::validate_artifact_size(path)
}

/// Same shape of check as `mylittlechart-server`'s
/// `pathutil::is_safe_path_component` — opsd does not depend on the server
/// crate, so this is a standalone copy. `platform`/`version` become literal
/// shell command and remote-path segments below; this doubles as the
/// injection guard.
fn is_safe_path_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Filename registered for this release, following the pre-existing
/// `mylittlechart-{platform}-{version}.{ext}` convention (the edges' static
/// `/dl/` layout assumes this shape). The extension comes from the actual
/// local artifact when it has a short ASCII one — a win64 client build IS an
/// `.exe`, a mac build might be `.dmg` — falling back to platform-based
/// inference only when the artifact carries none (a bare linux ELF, the only
/// case the old admin-route logic ever covered).
fn artifact_filename(platform: &str, version: &str, local: &Path) -> String {
    let candidate = local.extension().and_then(|e| e.to_str()).unwrap_or("");
    let ext = if !candidate.is_empty()
        && candidate.len() <= 8
        && candidate.chars().all(|c| c.is_ascii_alphanumeric())
    {
        candidate.to_lowercase()
    } else if platform.contains("win") {
        "exe".to_string()
    } else {
        "bin".to_string()
    };
    format!("mylittlechart-{platform}-{version}.{ext}")
}

/// Extract `ADMIN_SECRET=...` from the canonical `server.env` file
/// (KEY=VALUE per line — the same file `ops::unlock` pushes verbatim to the
/// box's tmpfs). Read locally instead of round-tripping through the box:
/// opsd already holds this file to deliver it on unlock.
fn admin_secret_from_env_file(bytes: &[u8]) -> Result<String, OpsdError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| OpsdError::CanonSecret("server.env is not utf-8".into()))?;
    text.lines()
        .find_map(|l| l.trim().strip_prefix("ADMIN_SECRET="))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OpsdError::CanonSecret("ADMIN_SECRET not found in server.env".into()))
}

/// `HTTP:<code>` / `BODY:<json>` lines emitted by the shell fragment built in
/// [`register_release`].
fn parse_register_response(stdout: &str) -> (Option<u16>, String) {
    let mut code = None;
    let mut body = String::new();
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("HTTP:") {
            code = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("BODY:") {
            body = v.to_string();
        }
    }
    (code, body)
}

/// A short random tag for scratch filenames on the box/edges — `publish` can
/// run concurrently within one long-lived daemon process, so a pid-based tag
/// would collide; this doesn't.
fn random_tag() -> String {
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Upload the artifact to one edge and sha256-verify it landed intact.
/// Returns the step description on success; the caller decides what to do
/// with a failure (unwind the edges that already succeeded).
async fn upload_and_verify_edge(
    state: &Arc<OpsdState>,
    edge: &EdgeConfig,
    bytes: &[u8],
    sha: &str,
    remote_dir: &str,
    remote_file: &str,
) -> Result<String, OpsdError> {
    let session = ops::connect_edge(state, edge).await?;

    let mkdir = session.exec(&format!("mkdir -p '{remote_dir}'")).await?;
    if mkdir.exit_code != Some(0) {
        return Err(OpsdError::Remote(format!(
            "edge {}: mkdir -p '{remote_dir}' failed: rc={:?} {}",
            edge.name,
            mkdir.exit_code,
            mkdir.stderr.trim()
        )));
    }

    // `SshSession::upload` IS the atomic primitive this needs: SFTP to
    // `<remote>.new`, verify the byte count on the wire, chmod, then rename
    // over the target (`ssh::upload_via_handle`). Mode matters here more
    // than anywhere else in this crate: an artifact that lands 0600 answers
    // 403 from nginx, and Cloudflare caches that 403 for a year on an
    // immutable-hinted path.
    session.upload(bytes, remote_file, 0o644).await?;

    let remote_sha_out = session.exec(&deploy::remote_sha256_cmd(remote_file)).await?;
    let remote_sha = deploy::parse_remote_sha256(&remote_sha_out.stdout).ok_or_else(|| {
        OpsdError::Remote(format!(
            "edge {}: unparsable remote sha256: {:?}",
            edge.name, remote_sha_out.stdout
        ))
    })?;
    if remote_sha != sha {
        let _ = session.exec(&format!("rm -f '{remote_file}'")).await;
        return Err(OpsdError::Remote(format!(
            "edge {}: sha256 mismatch after upload: local {sha} != remote {remote_sha} (removed)",
            edge.name
        )));
    }

    Ok(format!("edge {}: uploaded and sha256-verified {remote_file}", edge.name))
}

/// Best-effort removal of a file already confirmed uploaded to `edge` — used
/// to unwind a partial publish when a LATER edge fails. Errors are recorded
/// in `steps`, never propagated: cleanup must not hide the original failure
/// that triggered it.
async fn remove_from_edge(state: &Arc<OpsdState>, edge: &EdgeConfig, remote_file: &str, steps: &mut Vec<String>) {
    match ops::connect_edge(state, edge).await {
        Ok(session) => match session.exec(&format!("rm -f '{remote_file}'")).await {
            Ok(out) if out.exit_code == Some(0) || out.exit_code.is_none() => {
                steps.push(format!("rollback: removed {remote_file} from edge {}", edge.name));
            }
            Ok(out) => steps.push(format!(
                "rollback: rm on edge {} exited {:?}: {}",
                edge.name,
                out.exit_code,
                out.stderr.trim()
            )),
            Err(e) => steps.push(format!("rollback: rm on edge {} failed: {e}", edge.name)),
        },
        Err(e) => steps.push(format!(
            "rollback: could not reconnect to edge {} to clean up: {e}",
            edge.name
        )),
    }
}

/// Register the manifest row on the control box, reached only once every
/// edge has a verified copy of the artifact. The JSON body and the admin
/// secret are delivered as scratch files over SFTP (byte-exact, no shell
/// quoting hazard) and removed again by the same command that reads them;
/// `curl` on the box calls the box's own admin listener, resolved by
/// [`crate::state::APP_ADMIN_RESOLVE`] into `$A` — not the main app port,
/// since the 2026-09-22 admin-listener split moved `/api/admin/*` off that
/// port entirely.
///
/// The scratch files live under `/run` — tmpfs — not `/tmp`. This crate
/// already holds that line for the SQLCipher key it pushes on unlock, and a
/// bearer secret deserves the same treatment: if the session drops before the
/// cleanup runs, a `/tmp` copy survives on disk, while a `/run` one does not
/// survive a reboot and never reaches the platter at all.
async fn register_release(
    state: &Arc<OpsdState>,
    meta: &ReleaseMeta<'_>,
    steps: &mut Vec<String>,
) -> Result<(), OpsdError> {
    let env_bytes = std::fs::read(&state.box_cfg.canon_env_path)
        .map_err(|e| OpsdError::CanonSecret(format!("read server.env: {e}")))?;
    let admin_secret = admin_secret_from_env_file(&env_bytes)?;

    let payload = serde_json::json!({
        "platform": meta.platform,
        "version": meta.version,
        "channel": meta.channel,
        "filename": meta.filename,
        "sha256": meta.sha256,
        "file_size": meta.file_size,
        "release_notes": meta.release_notes,
        "signature": meta.signature,
    });
    let body = serde_json::to_vec(&payload)
        .map_err(|e| OpsdError::Remote(format!("encode register-release payload: {e}")))?;

    let session = ops::connect(state).await?;
    let tag = random_tag();
    let remote_body = format!("/run/mlc-opsd-release-{tag}.json");
    let remote_secret = format!("/run/mlc-opsd-admin-secret-{tag}");
    let remote_resp = format!("/run/mlc-opsd-release-resp-{tag}.json");

    session.upload(&body, &remote_body, 0o600).await?;
    session.upload(admin_secret.as_bytes(), &remote_secret, 0o600).await?;

    let cmd = format!(
        "{base}RC=$(curl -sS -o '{remote_resp}' -w '%{{http_code}}' -X POST \
           -H \"Authorization: Bearer $(cat '{remote_secret}')\" \
           -H 'Content-Type: application/json' \
           --data-binary @'{remote_body}' \
           \"$A/api/admin/register-release\"); \
         BODY=$(cat '{remote_resp}' 2>/dev/null); \
         rm -f '{remote_body}' '{remote_secret}' '{remote_resp}'; \
         echo \"HTTP:$RC\"; echo \"BODY:$BODY\"",
        base = crate::state::APP_ADMIN_RESOLVE,
    );
    let out = session.exec(&cmd).await?;
    let (code, body_text) = parse_register_response(&out.stdout);
    if code != Some(200) {
        return Err(OpsdError::Remote(format!(
            "register-release on control box failed: http={code:?} body={body_text} stderr={}",
            out.stderr.trim()
        )));
    }
    steps.push(format!("manifest row registered on control box (http {code:?})"));
    Ok(())
}

pub async fn publish(state: &Arc<OpsdState>, req: PublishRequest<'_>) -> Result<PublishOutcome, OpsdError> {
    let PublishRequest {
        local,
        platform,
        version,
        channel,
        release_notes,
        signature,
    } = req;

    if !is_safe_path_component(platform) || !is_safe_path_component(version) {
        return Err(OpsdError::Remote(format!(
            "platform ({platform:?}) and version ({version:?}) must be safe path components"
        )));
    }
    if channel != "stable" && channel != "dev" {
        return Err(OpsdError::Remote(format!(
            "channel must be 'stable' or 'dev', got {channel:?}"
        )));
    }
    if release_notes.len() > 4096 {
        return Err(OpsdError::Remote("release_notes too long (max 4096)".into()));
    }
    if signature.len() > 256 {
        return Err(OpsdError::Remote("signature too long (max 256)".into()));
    }

    let mut steps: Vec<String> = Vec::new();
    let size = validate_local_artifact(local)?;
    let bytes = std::fs::read(local)?;
    let sha = deploy::sha256_hex(&bytes);
    steps.push(format!("local artifact ok: {} bytes sha256={sha}", bytes.len()));

    let filename = artifact_filename(platform, version, local);
    let remote_dir = format!("{EDGE_STATIC_DL_ROOT}/{platform}/{version}");
    let remote_file = format!("{remote_dir}/{filename}");

    let mut done: Vec<&EdgeConfig> = Vec::new();
    for edge in &state.edges {
        match upload_and_verify_edge(state, edge, &bytes, &sha, &remote_dir, &remote_file).await {
            Ok(step) => {
                steps.push(step);
                done.push(edge);
            }
            Err(e) => {
                // A manifest row is registered ONLY after every edge
                // verifies — a row pointing at a file that is not on every
                // edge is worse than no release. Unwind whatever DID land.
                for ok_edge in &done {
                    remove_from_edge(state, ok_edge, &remote_file, &mut steps).await;
                }
                state.audit(
                    "release_publish",
                    &format!(
                        "ok=false platform={platform} version={version} channel={channel} \
                         sha256={sha} failed_edge={} err={e}",
                        edge.name
                    ),
                );
                return Err(OpsdError::Remote(format!(
                    "publish aborted: edge {} failed: {e}",
                    edge.name
                )));
            }
        }
    }
    steps.push(format!("verified on all {} edge(s)", state.edges.len()));

    let meta = ReleaseMeta {
        platform,
        version,
        channel,
        filename: &filename,
        sha256: &sha,
        file_size: size,
        release_notes,
        signature,
    };
    register_release(state, &meta, &mut steps).await?;

    state.audit(
        "release_publish",
        &format!(
            "ok=true platform={platform} version={version} channel={channel} \
             filename={filename} sha256={sha} size={size}"
        ),
    );
    Ok(PublishOutcome {
        ok: true,
        sha256: sha,
        size,
        filename,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_filename_uses_local_extension_when_present() {
        let p = Path::new("/tmp/build/chart-app-vello.exe");
        assert_eq!(artifact_filename("win64", "0.5.1", p), "mylittlechart-win64-0.5.1.exe");
        let p = Path::new("/tmp/build/mylittlechart.dmg");
        assert_eq!(artifact_filename("mac-arm64", "0.5.1", p), "mylittlechart-mac-arm64-0.5.1.dmg");
    }

    #[test]
    fn artifact_filename_falls_back_to_platform_inference_without_extension() {
        let p = Path::new("/tmp/build/mylittlechart-server");
        assert_eq!(artifact_filename("linux64", "0.5.1", p), "mylittlechart-linux64-0.5.1.bin");
        assert_eq!(artifact_filename("win64", "0.5.1", p), "mylittlechart-win64-0.5.1.exe");
    }

    #[test]
    fn is_safe_path_component_rejects_traversal_and_separators() {
        assert!(is_safe_path_component("win64"));
        assert!(is_safe_path_component("0.5.1"));
        assert!(!is_safe_path_component("../etc"));
        assert!(!is_safe_path_component(""));
        assert!(!is_safe_path_component("a/b"));
        assert!(!is_safe_path_component("a; rm -rf /"));
    }

    #[test]
    fn parse_register_response_reads_http_and_body_lines() {
        let (code, body) = parse_register_response("HTTP:200\nBODY:{\"status\":\"ok\"}\n");
        assert_eq!(code, Some(200));
        assert_eq!(body, "{\"status\":\"ok\"}");
    }

    #[test]
    fn parse_register_response_missing_lines_yields_none() {
        let (code, body) = parse_register_response("garbage output, no markers\n");
        assert_eq!(code, None);
        assert!(body.is_empty());
    }

    #[test]
    fn admin_secret_from_env_file_extracts_value() {
        let env = b"PORT=19200\nADMIN_SECRET=abc123\nOTHER=1\n";
        assert_eq!(admin_secret_from_env_file(env).unwrap(), "abc123");
    }

    #[test]
    fn admin_secret_from_env_file_missing_key_errors() {
        let env = b"PORT=19200\nOTHER=1\n";
        assert!(admin_secret_from_env_file(env).is_err());
    }

    #[test]
    fn random_tag_is_distinct_across_calls() {
        // Concurrent publishes on the same daemon must not collide on
        // scratch filenames — a pid-based tag would, since the pid is
        // constant for the whole process lifetime.
        assert_ne!(random_tag(), random_tag());
    }
}
