//! Decompose a whole `ChartPreset` JSON blob into the entity rows a shared
//! preset room stores, and reassemble a live room's entity rows back into
//! one preset (docs/mlc/plans/shared-presets-rights-and-live-sync-2026-09-23.md
//! §1/§3/§8).
//!
//! This server has no `mlc-core` dependency — `routes::share::clone_share`
//! already treats a preset as opaque `serde_json::Value` (walking
//! `preset["indicators"]` by raw key lookup, never deserializing into
//! `ChartPreset`), and this module does the same for every other part of the
//! shape. Field names below (`window_id`, `drawings.primitives`,
//! `stashed_primitives`, `symbol_drawings_snapshots`, a bubble's own `id`/
//! `primitives`, an indicator/alert's own `id`, `PrimitiveSnapshot`'s
//! `{type_id, json}` with the primitive's real id nested at
//! `data.id` inside that `json` STRING) are verified against
//! `mlc-core/src/preset/{preset,snapshots}.rs` and
//! `mlc-core/src/drawing/primitive_snapshot.rs` — kept in sync by hand, the
//! same way `clone_share`'s `type_id`/`name` lookups already are.
//!
//! Pure JSON-shape functions — no database, no `Connection` — so
//! `apply_room_patch`'s storage rows and this module's `DecomposedEntity`
//! are deliberately two different types (`routes::rooms` converts between
//! them at the boundary); keeping this module free of `db::
//! SharedPresetEntityRow` is what makes it unit-testable without a
//! database, per the plan's own testing note.

use serde_json::{Map, Value};

/// One entity `decompose_preset` pulled out of a whole preset, or one live
/// row `routes::rooms` hands to [`reassemble_preset`] after reading it back
/// from storage. `json` is already-parsed `Value`, not a serialized string —
/// `routes::rooms` is the one place that ever touches `serde_json::to_string`/
/// `from_str` on it, at the database boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct DecomposedEntity {
    /// `"window" | "bubble" | "indicator" | "alert" | "primitive" | "layout"`
    pub kind: String,
    pub entity_id: String,
    pub json: Value,
    /// Set only for `kind = "primitive"`: `"window"` or `"bubble"`.
    pub parent_kind: Option<String>,
    pub parent_id: Option<String>,
}

/// Every entity kind name this module ever produces — `routes::rooms` uses
/// this to validate an inbound patch op's `kind` before it ever reaches
/// `db::apply_room_patch`.
pub const ENTITY_KINDS: [&str; 6] = ["window", "bubble", "indicator", "alert", "primitive", "layout"];

/// The one `layout` entity's fixed id (a singleton per room).
pub const LAYOUT_ENTITY_ID: &str = "layout";

// ============================================================================
// decompose_preset
// ============================================================================

/// Split a whole preset JSON object into its entities (§1's table). Returns
/// `Err` on a structurally malformed preset (a required array/id field
/// missing or the wrong JSON type) — never panics on untrusted input.
pub fn decompose_preset(preset: &Value) -> Result<Vec<DecomposedEntity>, String> {
    let obj = preset.as_object().ok_or("preset must be a JSON object")?;
    let mut out = Vec::new();

    let windows = obj
        .get("windows")
        .and_then(Value::as_array)
        .ok_or("preset.windows must be an array")?;
    for win in windows {
        decompose_window(win, &mut out)?;
    }

    let bubbles = obj
        .get("bubbles")
        .and_then(Value::as_array)
        .ok_or("preset.bubbles must be an array")?;
    for bub in bubbles {
        decompose_bubble(bub, &mut out)?;
    }

    let indicators = obj
        .get("indicators")
        .and_then(Value::as_array)
        .ok_or("preset.indicators must be an array")?;
    for ind in indicators {
        let id = numeric_id(ind, "id").ok_or("indicator missing numeric id")?;
        out.push(DecomposedEntity {
            kind: "indicator".to_string(),
            entity_id: id,
            json: ind.clone(),
            parent_kind: None,
            parent_id: None,
        });
    }

    // `alerts` defaults to an empty vec client-side (`#[serde(default)]`) —
    // an older or minimal preset may omit the key entirely.
    if let Some(alerts) = obj.get("alerts").and_then(Value::as_array) {
        for alert in alerts {
            let id = numeric_id(alert, "id").ok_or("alert missing numeric id")?;
            out.push(DecomposedEntity {
                kind: "alert".to_string(),
                entity_id: id,
                json: alert.clone(),
                parent_kind: None,
                parent_id: None,
            });
        }
    }

    // The "layout" catch-all: everything that is not windows/bubbles/
    // indicators/alerts — `preset["layout"]`, `slot_layouts`, `slot_leaves`,
    // `leaf_color_tags` (the plan's own enumeration), PLUS the preset's own
    // `id`/`name`/`created_at`/`version` scalars, which the plan's table
    // does not separately name a home for. Taking "everything else"
    // literally (rather than the shorter enumerated list) is what makes
    // `reassemble_preset` lossless without inventing a place to stash those
    // four fields, and is forward-compatible with any future top-level
    // field this module was never updated to know about by name.
    let mut layout_json = preset.clone();
    if let Some(m) = layout_json.as_object_mut() {
        m.remove("windows");
        m.remove("bubbles");
        m.remove("indicators");
        m.remove("alerts");
    }
    out.push(DecomposedEntity {
        kind: "layout".to_string(),
        entity_id: LAYOUT_ENTITY_ID.to_string(),
        json: layout_json,
        parent_kind: None,
        parent_id: None,
    });

    Ok(out)
}

/// Read a numeric (`u64`) id field and stringify it — every window/bubble/
/// indicator/alert id in `mlc-core`'s snapshot types is a plain `u64`.
fn numeric_id(v: &Value, field: &str) -> Option<String> {
    v.get(field).and_then(Value::as_u64).map(|n| n.to_string())
}

fn decompose_window(win: &Value, out: &mut Vec<DecomposedEntity>) -> Result<(), String> {
    let window_id = numeric_id(win, "window_id").ok_or("window missing numeric window_id")?;
    let mut stripped = win.clone();

    let drawings_prims = stripped
        .get("drawings")
        .and_then(|d| d.get("primitives"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(drawings) = stripped.get_mut("drawings").and_then(Value::as_object_mut) {
        drawings.insert("primitives".to_string(), Value::Array(Vec::new()));
    }
    for prim in &drawings_prims {
        out.push(make_primitive_entity(prim, "window", &window_id, "drawings", None)?);
    }

    let stashed = stripped
        .get("stashed_primitives")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(obj) = stripped.as_object_mut() {
        obj.insert("stashed_primitives".to_string(), Value::Array(Vec::new()));
    }
    for prim in &stashed {
        out.push(make_primitive_entity(prim, "window", &window_id, "stashed_primitives", None)?);
    }

    let symbol_map = stripped
        .get("symbol_drawings_snapshots")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(obj) = stripped.as_object_mut() {
        obj.insert("symbol_drawings_snapshots".to_string(), Value::Object(Map::new()));
    }
    for (symbol, arr) in symbol_map.iter() {
        for prim in arr.as_array().into_iter().flatten() {
            out.push(make_primitive_entity(
                prim,
                "window",
                &window_id,
                "symbol_drawings_snapshots",
                Some(symbol.clone()),
            )?);
        }
    }

    out.push(DecomposedEntity {
        kind: "window".to_string(),
        entity_id: window_id,
        json: stripped,
        parent_kind: None,
        parent_id: None,
    });
    Ok(())
}

fn decompose_bubble(bub: &Value, out: &mut Vec<DecomposedEntity>) -> Result<(), String> {
    let bubble_id = numeric_id(bub, "id").ok_or("bubble missing numeric id")?;
    let mut stripped = bub.clone();

    let prims = stripped.get("primitives").and_then(Value::as_array).cloned().unwrap_or_default();
    if let Some(obj) = stripped.as_object_mut() {
        obj.insert("primitives".to_string(), Value::Array(Vec::new()));
    }
    for prim in &prims {
        out.push(make_primitive_entity(prim, "bubble", &bubble_id, "primitives", None)?);
    }

    out.push(DecomposedEntity {
        kind: "bubble".to_string(),
        entity_id: bubble_id,
        json: stripped,
        parent_kind: None,
        parent_id: None,
    });
    Ok(())
}

/// Build a `primitive` entity from one raw `PrimitiveSnapshot`-shaped value
/// (`{"type_id": "...", "json": "<embedded JSON string>"}`). `entity_id` is
/// [`PrimitiveSnapshot::id()`]'s value read out of that embedded string
/// (`data.id`) — already stable and process-unique post-
/// `remap_ids_for_import` (plan §1).
fn make_primitive_entity(
    prim: &Value,
    parent_kind: &str,
    parent_id: &str,
    collection: &str,
    symbol: Option<String>,
) -> Result<DecomposedEntity, String> {
    let entity_id = primitive_entity_id(prim)?;
    let mut payload = Map::new();
    payload.insert("collection".to_string(), Value::String(collection.to_string()));
    if let Some(sym) = symbol {
        payload.insert("symbol".to_string(), Value::String(sym));
    }
    payload.insert("primitive".to_string(), prim.clone());
    Ok(DecomposedEntity {
        kind: "primitive".to_string(),
        entity_id,
        json: Value::Object(payload),
        parent_kind: Some(parent_kind.to_string()),
        parent_id: Some(parent_id.to_string()),
    })
}

/// Read a `PrimitiveSnapshot`'s own id: `prim.json` is a STRING (the
/// primitive's own serialized state, `PrimitiveSnapshot::json`), parsed as
/// JSON, then `.data.id` read off of THAT — mirrors
/// `PrimitiveSnapshot::id()` exactly (mlc-core/src/drawing/
/// primitive_snapshot.rs), since this crate cannot call that method
/// directly (no `mlc-core` dependency).
fn primitive_entity_id(prim: &Value) -> Result<String, String> {
    let inner = prim
        .get("json")
        .and_then(Value::as_str)
        .ok_or("primitive missing its own json string field")?;
    let parsed: Value = serde_json::from_str(inner).map_err(|e| format!("primitive json is not valid JSON: {e}"))?;
    let id = parsed
        .get("data")
        .and_then(|d| d.get("id"))
        .and_then(Value::as_u64)
        .ok_or("primitive json missing data.id")?;
    Ok(id.to_string())
}

// ============================================================================
// reassemble_preset
// ============================================================================

/// The exact inverse of [`decompose_preset`]: re-nest every `primitive`
/// entity back into its parent window's `drawings.primitives`/
/// `stashed_primitives`/`symbol_drawings_snapshots[symbol]`, or the owning
/// bubble's `primitives`, then rebuild `windows`/`bubbles`/`indicators`/
/// `alerts` on top of the `layout` entity's json (which already carries
/// every other top-level preset field — see the comment in
/// `decompose_preset`). `entities` is expected to hold only LIVE entities
/// (no tombstones) — `routes::rooms` feeds this from `db::room_live_entities`,
/// never `db::room_entities_since`.
pub fn reassemble_preset(entities: &[DecomposedEntity]) -> Value {
    let mut base: Map<String, Value> = entities
        .iter()
        .find(|e| e.kind == "layout" && e.entity_id == LAYOUT_ENTITY_ID)
        .and_then(|e| e.json.as_object().cloned())
        .unwrap_or_default();

    let windows: Vec<Value> = entities
        .iter()
        .filter(|e| e.kind == "window")
        .map(|e| {
            let mut w = e.json.clone();
            nest_window_primitives(&mut w, &e.entity_id, entities);
            w
        })
        .collect();
    base.insert("windows".to_string(), Value::Array(windows));

    let bubbles: Vec<Value> = entities
        .iter()
        .filter(|e| e.kind == "bubble")
        .map(|e| {
            let mut b = e.json.clone();
            let prims = primitives_for_parent(entities, "bubble", &e.entity_id);
            if let Some(obj) = b.as_object_mut() {
                obj.insert("primitives".to_string(), Value::Array(prims));
            }
            b
        })
        .collect();
    base.insert("bubbles".to_string(), Value::Array(bubbles));

    let indicators: Vec<Value> = entities.iter().filter(|e| e.kind == "indicator").map(|e| e.json.clone()).collect();
    base.insert("indicators".to_string(), Value::Array(indicators));

    let alerts: Vec<Value> = entities.iter().filter(|e| e.kind == "alert").map(|e| e.json.clone()).collect();
    base.insert("alerts".to_string(), Value::Array(alerts));

    Value::Object(base)
}

/// Every `primitive` entity's raw `PrimitiveSnapshot` value (the `primitive`
/// field of its payload), parented to `(parent_kind, parent_id)`, in
/// `entities`' own relative order.
fn primitives_for_parent(entities: &[DecomposedEntity], parent_kind: &str, parent_id: &str) -> Vec<Value> {
    entities
        .iter()
        .filter(|e| e.kind == "primitive" && e.parent_kind.as_deref() == Some(parent_kind) && e.parent_id.as_deref() == Some(parent_id))
        .map(|e| e.json.get("primitive").cloned().unwrap_or(Value::Null))
        .collect()
}

fn nest_window_primitives(window: &mut Value, window_id: &str, entities: &[DecomposedEntity]) {
    let mut drawings_prims = Vec::new();
    let mut stashed_prims = Vec::new();
    let mut symbol_map: Map<String, Value> = Map::new();

    for e in entities
        .iter()
        .filter(|e| e.kind == "primitive" && e.parent_kind.as_deref() == Some("window") && e.parent_id.as_deref() == Some(window_id))
    {
        let collection = e.json.get("collection").and_then(Value::as_str).unwrap_or("drawings");
        let primitive = e.json.get("primitive").cloned().unwrap_or(Value::Null);
        match collection {
            "stashed_primitives" => stashed_prims.push(primitive),
            "symbol_drawings_snapshots" => {
                let symbol = e.json.get("symbol").and_then(Value::as_str).unwrap_or("").to_string();
                let entry = symbol_map.entry(symbol).or_insert_with(|| Value::Array(Vec::new()));
                if let Some(arr) = entry.as_array_mut() {
                    arr.push(primitive);
                }
            }
            // "drawings" and any value this module does not recognise both
            // default to the main drawing collection.
            _ => drawings_prims.push(primitive),
        }
    }

    if let Some(drawings) = window.get_mut("drawings").and_then(Value::as_object_mut) {
        drawings.insert("primitives".to_string(), Value::Array(drawings_prims));
    }
    if let Some(obj) = window.as_object_mut() {
        obj.insert("stashed_primitives".to_string(), Value::Array(stashed_prims));
        obj.insert("symbol_drawings_snapshots".to_string(), Value::Object(symbol_map));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `PrimitiveSnapshot`-shaped fixture value with the given id
    /// embedded at `data.id`, matching `PrimitiveSnapshot::id()`'s read path.
    fn primitive_fixture(type_id: &str, id: u64) -> Value {
        let inner = serde_json::json!({ "data": { "id": id, "x1": 1.0, "y1": 2.0 } });
        serde_json::json!({
            "type_id": type_id,
            "json": serde_json::to_string(&inner).expect("serialize inner"),
        })
    }

    /// A fixture preset carrying one window with all three primitive
    /// collections (`drawings.primitives`, `stashed_primitives`,
    /// `symbol_drawings_snapshots` with 2 symbol keys) and one bubble with
    /// its own `primitives` — the exact shape the plan's Phase 1 test list
    /// asks for.
    fn sample_preset() -> Value {
        serde_json::json!({
            "id": "preset_123_abc",
            "name": "Room fixture",
            "created_at": 1_700_000_000u64,
            "version": 1,
            "layout": { "kind": "leaf", "id": 1 },
            "slot_layouts": [null, null],
            "slot_leaves": [[], []],
            "leaf_color_tags": { "1": [1.0, 0.0, 0.0, 1.0] },
            "windows": [
                {
                    "window_id": 10,
                    "leaf_id": 1,
                    "symbol": "BTCUSDT",
                    "drawings": {
                        "window_id": 10,
                        "primitives": [primitive_fixture("trend_line", 101)],
                    },
                    "stashed_primitives": [primitive_fixture("fib_retracement", 102)],
                    "symbol_drawings_snapshots": {
                        "BTCUSDT:binance:S": [primitive_fixture("rectangle", 103)],
                        "ETHUSDT:binance:S": [
                            primitive_fixture("rectangle", 104),
                            primitive_fixture("trend_line", 105),
                        ],
                    },
                }
            ],
            "bubbles": [
                {
                    "id": 20,
                    "color": [1.0, 1.0, 1.0, 1.0],
                    "symbol": "BTCUSDT",
                    "members": [10],
                    "primitives": [primitive_fixture("horizontal_line", 201)],
                }
            ],
            "indicators": [
                { "id": 30, "type_id": "sma", "name": "SMA", "params": {} }
            ],
            "alerts": [
                { "id": 40, "name": "Alert 1", "price": 100.0 }
            ],
        })
    }

    #[test]
    fn decompose_splits_every_primitive_into_its_own_entity_with_correct_parent() {
        let preset = sample_preset();
        let entities = decompose_preset(&preset).expect("decompose");

        let primitives: Vec<&DecomposedEntity> = entities.iter().filter(|e| e.kind == "primitive").collect();
        assert_eq!(primitives.len(), 6, "5 window primitives + 1 bubble primitive");

        let by_id = |id: &str| primitives.iter().find(|e| e.entity_id == id).unwrap_or_else(|| panic!("missing primitive {id}"));

        let drawings_prim = by_id("101");
        assert_eq!(drawings_prim.parent_kind.as_deref(), Some("window"));
        assert_eq!(drawings_prim.parent_id.as_deref(), Some("10"));
        assert_eq!(drawings_prim.json.get("collection").and_then(Value::as_str), Some("drawings"));
        assert!(drawings_prim.json.get("symbol").is_none());

        let stashed_prim = by_id("102");
        assert_eq!(stashed_prim.json.get("collection").and_then(Value::as_str), Some("stashed_primitives"));

        let symbol_prim_btc = by_id("103");
        assert_eq!(symbol_prim_btc.json.get("collection").and_then(Value::as_str), Some("symbol_drawings_snapshots"));
        assert_eq!(symbol_prim_btc.json.get("symbol").and_then(Value::as_str), Some("BTCUSDT:binance:S"));

        let symbol_prim_eth_a = by_id("104");
        let symbol_prim_eth_b = by_id("105");
        assert_eq!(symbol_prim_eth_a.json.get("symbol").and_then(Value::as_str), Some("ETHUSDT:binance:S"));
        assert_eq!(symbol_prim_eth_b.json.get("symbol").and_then(Value::as_str), Some("ETHUSDT:binance:S"));

        let bubble_prim = by_id("201");
        assert_eq!(bubble_prim.parent_kind.as_deref(), Some("bubble"));
        assert_eq!(bubble_prim.parent_id.as_deref(), Some("20"));
        assert_eq!(bubble_prim.json.get("collection").and_then(Value::as_str), Some("primitives"));
    }

    #[test]
    fn decompose_strips_primitive_collections_out_of_the_window_and_bubble_entities() {
        let preset = sample_preset();
        let entities = decompose_preset(&preset).expect("decompose");

        let window = entities.iter().find(|e| e.kind == "window").expect("window entity");
        assert_eq!(window.json["drawings"]["primitives"].as_array().expect("array").len(), 0);
        assert_eq!(window.json["stashed_primitives"].as_array().expect("array").len(), 0);
        assert_eq!(window.json["symbol_drawings_snapshots"].as_object().expect("object").len(), 0);

        let bubble = entities.iter().find(|e| e.kind == "bubble").expect("bubble entity");
        assert_eq!(bubble.json["primitives"].as_array().expect("array").len(), 0);
    }

    #[test]
    fn decompose_produces_one_indicator_one_alert_and_one_layout_entity() {
        let preset = sample_preset();
        let entities = decompose_preset(&preset).expect("decompose");

        let indicator = entities.iter().find(|e| e.kind == "indicator").expect("indicator entity");
        assert_eq!(indicator.entity_id, "30");

        let alert = entities.iter().find(|e| e.kind == "alert").expect("alert entity");
        assert_eq!(alert.entity_id, "40");

        let layout = entities.iter().find(|e| e.kind == "layout").expect("layout entity");
        assert_eq!(layout.entity_id, LAYOUT_ENTITY_ID);
        assert_eq!(layout.json.get("id").and_then(Value::as_str), Some("preset_123_abc"));
        assert!(layout.json.get("windows").is_none());
        assert!(layout.json.get("bubbles").is_none());
        assert!(layout.json.get("indicators").is_none());
        assert!(layout.json.get("alerts").is_none());
    }

    #[test]
    fn reassemble_reproduces_the_exact_original_preset() {
        let preset = sample_preset();
        let entities = decompose_preset(&preset).expect("decompose");
        let reassembled = reassemble_preset(&entities);
        assert_eq!(reassembled, preset);
    }

    #[test]
    fn reassemble_of_an_empty_entity_list_is_an_empty_object_with_empty_arrays() {
        let reassembled = reassemble_preset(&[]);
        assert_eq!(
            reassembled,
            serde_json::json!({ "windows": [], "bubbles": [], "indicators": [], "alerts": [] })
        );
    }

    #[test]
    fn decompose_rejects_a_primitive_missing_data_id() {
        let mut preset = sample_preset();
        preset["windows"][0]["drawings"]["primitives"][0] = serde_json::json!({
            "type_id": "trend_line",
            "json": "{\"data\":{}}",
        });
        assert!(decompose_preset(&preset).is_err());
    }

    #[test]
    fn decompose_rejects_a_non_object_preset() {
        assert!(decompose_preset(&serde_json::json!([1, 2, 3])).is_err());
    }

    #[test]
    fn decompose_rejects_a_window_missing_window_id() {
        let mut preset = sample_preset();
        preset["windows"][0].as_object_mut().expect("object").remove("window_id");
        assert!(decompose_preset(&preset).is_err());
    }

    #[test]
    fn decompose_treats_a_missing_alerts_array_as_no_alerts() {
        let mut preset = sample_preset();
        preset.as_object_mut().expect("object").remove("alerts");
        let entities = decompose_preset(&preset).expect("decompose");
        assert!(entities.iter().all(|e| e.kind != "alert"));
    }
}
