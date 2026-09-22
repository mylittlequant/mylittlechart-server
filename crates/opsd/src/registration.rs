//! Builds the `nemo_service::manifest::ServiceManifest` `mlc-opsd` asserts
//! about itself via `PUT /registry/:name` — see `crate::api::serve` for
//! where it is registered.
//!
//! The `[service]`, `[links]`, `[[manage_actions]]` and `[dependencies]`
//! content here is carried over verbatim from the now-deleted
//! `.nemo-services/mlc-opsd.toml` (the file this manifest replaces) — it was
//! the description last verified against the running code, so nothing below
//! is invented. `endpoints` is NOT here: it comes from `crate::api`'s
//! `DocRouter` build, a by-product of the router itself, which is the whole
//! point of this conversion (see
//! `nemo/docs/d-watchdog/plans/service-registration-and-pid-ownership-2026-09-22.md`).

use nemo_service::manifest::{
    Dependencies, Endpoint, HealthInfo, Links, ManageAction, ServiceManifest, ServiceMeta,
};

/// Verbatim from the retired `.nemo-services/mlc-opsd.toml`'s `[service]`
/// `description`. Split across lines with `\`-continuations (no embedded
/// newlines) purely so this file stays readable — the resulting string is
/// one paragraph, unchanged.
const SERVICE_DESCRIPTION: &str = "Operator control plane for the mylittlechart.org production fleet — runs on \
the operator's workstation (opbox), NOT on any served box. It is the only tool allowed to reach the fleet: SSH to \
the control box (mlc-c2-1, holds identity/social/sync data) and both public edges (mlc-utah-1, mlc-ams-1, \
nginx-only). This is not the mylittlechart.org backend itself (see mylittlechart-server's own .nemo-service.toml) \
— it deploys, publishes, unlocks and backs that backend up. Capabilities: deploy a musl server binary to control \
with health-verified auto-rollback, publish a signed release artifact to both edges then register its manifest on \
control, boot-unlock (push the SQLCipher key + server.env to control's tmpfs and start mlc-server), pull encrypted \
backups to the opbox, restart a whitelisted systemd unit (mlc-server/nginx/nftables/fail2ban), and an autonomous \
60s watch loop that detects control being down for the key and unlocks it without operator action.";

/// One read-only `GET` manage action: same shape for all five of
/// `mlc-opsd`'s actions (bearer, no confirm, no body) — see the retired
/// file's `[[manage_actions]]` blocks.
fn get_action(id: &str, label: &str, description: &str, path: &str) -> ManageAction {
    ManageAction {
        id: id.to_string(),
        label: label.to_string(),
        description: Some(description.to_string()),
        method: "GET".to_string(),
        path: path.to_string(),
        auth: "bearer".to_string(),
        key_ref: None,
        confirm: false,
        icon: None,
        body: None,
        content_type: None,
        timeout_secs: None,
        mode: None,
        params_schema: Vec::new(),
    }
}

/// Build the manifest `mlc-opsd` asserts about itself. `endpoints` is the
/// list `crate::api::build_router` recorded while building the real router —
/// passed in rather than rebuilt here so there is exactly one place a route
/// is described.
pub(crate) fn service_manifest(endpoints: Vec<Endpoint>) -> ServiceManifest {
    ServiceManifest {
        service: ServiceMeta {
            name: "mlc-opsd".to_string(),
            kind: "http_api".to_string(),
            display_name: Some("mlc-opsd".to_string()),
            description: Some(SERVICE_DESCRIPTION.to_string()),
            version: None,
            // opsd's own bearer is a generated 32-byte hex token at
            // `<state_dir>/api-key` (`state::load_or_generate_api_key`), not
            // a `VAR=value` line in a `nemo/env/*.env` file — key_ref's
            // `<path>:<VAR>` shape has nothing to point at here.
            key_ref: None,
        },
        links: Links {
            public_url: None,
            // The retired file hardcoded `http://127.0.0.1:18360`, but the
            // daemon's own bind address is already an override-able fact
            // (`crate::state::bind_addr`, `MLC_OPSD_BIND` for a side-by-side
            // test instance) — reading it back here means this field can
            // never drift from what the daemon actually bound to.
            local_url: Some(format!("http://{}", crate::state::bind_addr())),
            admin_url: None,
            docs: Some("mylittlechart-server/ops/README.md".to_string()),
            repo: None,
        },
        endpoints,
        manage_actions: vec![
            get_action(
                "status",
                "Fleet Status",
                "Read-only: systemd unit states, app health, disk/mem, uptime on the control box.",
                "/api/status",
            ),
            get_action(
                "box_state",
                "Box Unlock State",
                "Read-only: whether the SQLCipher key is present in control's tmpfs and whether the boot journal is stuck waiting for it.",
                "/api/box/state",
            ),
            get_action(
                "backup_list",
                "List Local Backups",
                "Read-only: opbox-side encrypted backup archive listing.",
                "/api/backup/list",
            ),
            get_action(
                "watch_state",
                "Watch Loop State",
                "Read-only: watch-loop miss counters and last intervention.",
                "/api/watch/state",
            ),
            get_action(
                "logs",
                "Journal Tail",
                "Read-only: journal tail for a whitelisted unit on control (query unit=, lines=).",
                "/api/logs",
            ),
        ],
        // Reaches the control box and both public edges over SSH; none of
        // them are local d-watchdog processes, so nothing is named here —
        // same reasoning the retired file's `[dependencies]` comment gave.
        dependencies: Dependencies::default(),
        health: Some(HealthInfo {
            endpoint: "/health".to_string(),
            expected_status: 200,
            interval_secs: 30,
        }),
    }
}
