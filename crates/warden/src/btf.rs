//! Minimal raw BTF (BPF Type Format) parser — struct member byte-offset
//! resolution only. Consumed by `bpf_lsm::loader::resolve_kernel_offsets`
//! (Linux-only) to make mlc-warden's Tier-2 BPF-LSM kernel-agnostic: at load
//! time, the loader reads `/sys/kernel/btf/vmlinux` and calls
//! [`resolve_member_offset`] for each of the 8 struct fields
//! `warden-ebpf/src/cgroup.rs` and `main.rs` need, instead of relying on the
//! hardcoded KERNEL 6.8.0-130-generic table in `warden-ebpf/src/vmlinux.rs`.
//!
//! Ported verbatim from mirage-secd's `kernel_btf_offsets.rs`.
//!
//! This module itself has NO Linux dependency (pure byte parsing over an
//! in-memory blob) — it lives outside the `bpf_lsm` tree's
//! `#[cfg(target_os = "linux")]` gate specifically so its unit tests run on
//! every dev box, including the Windows box this crate is normally
//! `cargo build`ed from.
//!
//! # Why not `aya::Btf`
//!
//! `aya` 0.14 / `aya-obj` 0.3 parse BTF internally (`Btf::from_sys_fs` is
//! already used in `bpf_lsm::loader` for `Lsm::load`'s relocation argument),
//! but every type accessor needed to walk a struct's members and read a
//! member's byte offset is `pub(crate)` inside `aya-obj` — there is no
//! public API surface for "given a struct name and a member name, give me
//! the byte offset". Rather than vendor/patch `aya-obj`, this module parses
//! the raw BTF binary blob directly against the documented, stable kernel
//! UAPI layout (`include/uapi/linux/btf.h`), which does not change between
//! aya versions.
//!
//! # Binary layout (matches `aya-obj`'s own internal parser, cross-checked
//! against its generated bindings in
//! `aya-obj-0.3.0/src/generated/linux_bindings_x86_64.rs`)
//!
//! ```text
//! struct btf_header {          // 24 bytes, all little-endian on every
//!     u16 magic;                // fleet architecture (x86_64)
//!     u8  version;
//!     u8  flags;
//!     u32 hdr_len;
//!     u32 type_off;             // relative to end of header (hdr_len)
//!     u32 type_len;
//!     u32 str_off;              // relative to end of header (hdr_len)
//!     u32 str_len;
//! }
//!
//! struct btf_type {             // 12-byte fixed head, kind-specific tail
//!     u32 name_off;              // offset into string section
//!     u32 info;                  // bit 31 = kflag, bits 24..=28 = kind,
//!                                 // bits 0..=15 = vlen (member count for
//!                                 // STRUCT/UNION)
//!     union { u32 size; u32 type; }
//! }
//! // BTF_KIND_STRUCT / BTF_KIND_UNION: `vlen` trailing btf_member entries
//! struct btf_member {           // 12 bytes
//!     u32 name_off;
//!     u32 type;                 // member's own BTF type id (unused here)
//!     u32 offset;                // bit_offset, OR (if kflag) bitfield-packed:
//!                                 // low 24 bits = bit_offset, high 8 = bitsize
//! }
//! ```
//!
//! Type id `0` is reserved (`void`); the first parsed type in the type
//! section is id `1`, incrementing sequentially — this matches
//! `aya-obj::btf::Btf::read_type_info`'s own indexing.
//!
//! Every field read here (name lookup, member walk) mirrors the semantics
//! `aya-obj` already implements for its own (crate-private) equivalents —
//! this is not a novel format, just a public re-implementation of the
//! documented layout aya keeps private.

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_HEADER_LEN: usize = 24;
const BTF_TYPE_HEAD_LEN: usize = 12;
const BTF_MEMBER_LEN: usize = 12;

/// Byte offset of a single resolved struct member, or the reason resolution
/// failed — never panics, every failure is a plain `String` reason for the
/// caller to log and fall back on.
pub type OffsetResult = Result<usize, String>;

/// Resolve the byte offset of `struct_name.member_name` from a raw BTF blob
/// (as read from `/sys/kernel/btf/vmlinux`).
///
/// Returns the member's byte offset (`bit_offset / 8`) if found and the
/// member is not a genuine sub-byte bitfield (this module only expects
/// pointer/`u64` fields — a resolved bitfield is treated as "not found"
/// since none of the fields the warden needs are ever declared as C
/// bitfields on any real kernel).
pub fn resolve_member_offset(
    btf_bytes: &[u8],
    struct_name: &str,
    member_name: &str,
) -> OffsetResult {
    let header = read_header(btf_bytes)?;

    let type_base = header.hdr_len as usize + header.type_off as usize;
    let type_end = type_base
        .checked_add(header.type_len as usize)
        .ok_or_else(|| "type section end overflow".to_string())?;
    let str_base = header.hdr_len as usize + header.str_off as usize;
    let str_end = str_base
        .checked_add(header.str_len as usize)
        .ok_or_else(|| "string section end overflow".to_string())?;

    if type_end > btf_bytes.len() || str_end > btf_bytes.len() {
        return Err("BTF section bounds exceed blob length".to_string());
    }

    let type_section = &btf_bytes[type_base..type_end];
    let str_section = &btf_bytes[str_base..str_end];

    let mut cursor = 0usize;
    while cursor < type_section.len() {
        if cursor + BTF_TYPE_HEAD_LEN > type_section.len() {
            return Err("truncated BTF type header".to_string());
        }
        let name_off = read_u32(type_section, cursor)?;
        let info = read_u32(type_section, cursor + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kflag = info >> 31 == 1;

        // Every kind's on-disk size beyond the 12-byte head, so the cursor
        // can advance to the next type regardless of whether this one is
        // the struct we're looking for.
        let tail_len = kind_tail_len(kind, vlen)?;
        let type_total_len = BTF_TYPE_HEAD_LEN + tail_len;
        if cursor + type_total_len > type_section.len() {
            return Err("truncated BTF type body".to_string());
        }

        if kind == BTF_KIND_STRUCT && string_at(str_section, name_off)? == struct_name {
            let members_start = cursor + BTF_TYPE_HEAD_LEN;
            for m in 0..vlen {
                let member_off = members_start + m * BTF_MEMBER_LEN;
                let m_name_off = read_u32(type_section, member_off)?;
                let m_offset_raw = read_u32(type_section, member_off + 8)?;

                if string_at(str_section, m_name_off)? == member_name {
                    let bitsize = if kflag { m_offset_raw >> 24 } else { 0 };
                    if bitsize != 0 {
                        return Err(format!(
                            "{struct_name}.{member_name} is a {bitsize}-bit bitfield — unsupported"
                        ));
                    }
                    let bit_offset = if kflag { m_offset_raw & 0x00ff_ffff } else { m_offset_raw };
                    if bit_offset % 8 != 0 {
                        return Err(format!(
                            "{struct_name}.{member_name} bit_offset {bit_offset} not byte-aligned"
                        ));
                    }
                    return Ok((bit_offset / 8) as usize);
                }
            }
            return Err(format!("struct {struct_name} has no member {member_name}"));
        }

        cursor += type_total_len;
    }

    Err(format!("struct {struct_name} not found in BTF"))
}

struct Header {
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
}

fn read_header(data: &[u8]) -> Result<Header, String> {
    if data.len() < BTF_HEADER_LEN {
        return Err("BTF blob shorter than header".to_string());
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC {
        return Err(format!("bad BTF magic 0x{magic:04x}"));
    }
    Ok(Header {
        hdr_len: read_u32(data, 4)?,
        type_off: read_u32(data, 8)?,
        type_len: read_u32(data, 12)?,
        str_off: read_u32(data, 16)?,
        str_len: read_u32(data, 20)?,
    })
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| format!("BTF read out of bounds at {offset}"))?
        .try_into()
        .map_err(|_| format!("BTF read out of bounds at {offset}"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// NUL-terminated string lookup within the BTF string section, mirroring
/// `aya_obj::btf::Btf::string_at`'s own semantics (offset indexes directly
/// into the extracted string-section slice, string ends at the first NUL
/// byte).
fn string_at(str_section: &[u8], offset: u32) -> Result<&str, String> {
    let offset = offset as usize;
    let tail = str_section
        .get(offset..)
        .ok_or_else(|| format!("BTF string offset {offset} out of bounds"))?;
    let nul_pos = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| format!("BTF string at offset {offset} not NUL-terminated"))?;
    core::str::from_utf8(&tail[..nul_pos])
        .map_err(|e| format!("BTF string at offset {offset} not UTF-8: {e}"))
}

/// Byte length of the kind-specific trailing data following the fixed
/// 12-byte `btf_type` head, for the kinds this parser can encounter while
/// scanning past irrelevant types. Matches
/// `aya_obj::btf::types::BtfType::type_info_size`'s own per-kind byte
/// accounting (cross-checked against its `read`/`to_bytes` implementations
/// for each kind, `aya-obj-0.3.0/src/btf/types.rs`).
fn kind_tail_len(kind: u32, vlen: usize) -> Result<usize, String> {
    const BTF_KIND_INT: u32 = 1;
    const BTF_KIND_PTR: u32 = 2;
    const BTF_KIND_ARRAY: u32 = 3;
    const BTF_KIND_UNION: u32 = 5;
    const BTF_KIND_ENUM: u32 = 6;
    const BTF_KIND_FWD: u32 = 7;
    const BTF_KIND_TYPEDEF: u32 = 8;
    const BTF_KIND_VOLATILE: u32 = 9;
    const BTF_KIND_CONST: u32 = 10;
    const BTF_KIND_RESTRICT: u32 = 11;
    const BTF_KIND_FUNC: u32 = 12;
    const BTF_KIND_FUNC_PROTO: u32 = 13;
    const BTF_KIND_VAR: u32 = 14;
    const BTF_KIND_DATASEC: u32 = 15;
    const BTF_KIND_FLOAT: u32 = 16;
    const BTF_KIND_DECL_TAG: u32 = 17;
    const BTF_KIND_TYPE_TAG: u32 = 18;
    const BTF_KIND_ENUM64: u32 = 19;

    // BTF_KIND_UNKN (0) has no trailing data either.
    Ok(match kind {
        0 | BTF_KIND_FWD | BTF_KIND_PTR | BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE | BTF_KIND_CONST
        | BTF_KIND_RESTRICT | BTF_KIND_FUNC | BTF_KIND_TYPE_TAG => 0,
        BTF_KIND_INT => 4,
        BTF_KIND_FLOAT => 0,
        BTF_KIND_ARRAY => 12, // btf_array { type, index_type, nelems }
        BTF_KIND_STRUCT | BTF_KIND_UNION => vlen * BTF_MEMBER_LEN,
        BTF_KIND_ENUM => vlen * 8,   // btf_enum { name_off: u32, val: i32 }
        BTF_KIND_ENUM64 => vlen * 12, // btf_enum64 { name_off, val_lo32, val_hi32 }
        BTF_KIND_FUNC_PROTO => vlen * 8, // btf_param { name_off, type }
        BTF_KIND_VAR => 4,           // btf_var { linkage: u32 }
        BTF_KIND_DATASEC => vlen * 12, // btf_var_secinfo { type, offset, size }
        BTF_KIND_DECL_TAG => 4,      // component_idx: i32
        other => return Err(format!("unknown BTF kind {other}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-builds a minimal synthetic BTF blob containing exactly one
    /// struct (`struct probe { u64 pad; void *needle; }`) and asserts the
    /// parser resolves `needle`'s byte offset correctly — the same mechanism
    /// `resolve_member_offset` uses against `/sys/kernel/btf/vmlinux` in
    /// production, exercised here against a known-good hand-built blob
    /// rather than requiring a live Linux kernel (this crate's test suite
    /// runs on the Windows dev box too).
    fn build_synthetic_btf(
        struct_name: &str,
        member_name: &str,
        member_byte_offset: u32,
    ) -> Vec<u8> {
        // String section: NUL, then struct_name\0, then member_name\0
        // (offset 0 is always the empty string per BTF convention).
        let mut strings = vec![0u8];
        let struct_name_off = strings.len() as u32;
        strings.extend_from_slice(struct_name.as_bytes());
        strings.push(0);
        let member_name_off = strings.len() as u32;
        strings.extend_from_slice(member_name.as_bytes());
        strings.push(0);

        // One BTF_KIND_STRUCT type, vlen=2, kflag=0, two members: a
        // preceding pad member at offset 0, then `member_name` at
        // `member_byte_offset` (so a real "read the correct member, not
        // just the first one" bug would be caught).
        let pad_name = strings.len() as u32;
        strings.extend_from_slice(b"pad");
        strings.push(0);

        let kind = BTF_KIND_STRUCT;
        let vlen: u32 = 2;
        let info = (kind << 24) | vlen;

        let mut types = Vec::new();
        types.extend_from_slice(&struct_name_off.to_le_bytes());
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes()); // struct size, unused

        // member 0: pad, offset 0 (bit offset)
        types.extend_from_slice(&pad_name.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes()); // member type id, unused
        types.extend_from_slice(&0u32.to_le_bytes()); // bit_offset = 0

        // member 1: the needle, at member_byte_offset * 8 bits
        types.extend_from_slice(&member_name_off.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&(member_byte_offset * 8).to_le_bytes());

        let hdr_len = BTF_HEADER_LEN as u32;
        let type_off = 0u32;
        let type_len = types.len() as u32;
        let str_off = type_len; // strings placed immediately after types
        let str_len = strings.len() as u32;

        let mut blob = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&hdr_len.to_le_bytes());
        blob.extend_from_slice(&type_off.to_le_bytes());
        blob.extend_from_slice(&type_len.to_le_bytes());
        blob.extend_from_slice(&str_off.to_le_bytes());
        blob.extend_from_slice(&str_len.to_le_bytes());
        blob.extend_from_slice(&types);
        blob.extend_from_slice(&strings);
        blob
    }

    #[test]
    fn resolves_known_member_offset() {
        let blob = build_synthetic_btf("probe_struct", "needle_field", 3656);
        let offset = resolve_member_offset(&blob, "probe_struct", "needle_field")
            .expect("resolution should succeed against a well-formed synthetic blob");
        assert_eq!(offset, 3656);
    }

    #[test]
    fn missing_struct_is_err() {
        let blob = build_synthetic_btf("probe_struct", "needle_field", 128);
        assert!(resolve_member_offset(&blob, "no_such_struct", "needle_field").is_err());
    }

    #[test]
    fn missing_member_is_err() {
        let blob = build_synthetic_btf("probe_struct", "needle_field", 128);
        assert!(resolve_member_offset(&blob, "probe_struct", "no_such_member").is_err());
    }

    #[test]
    fn bad_magic_is_err() {
        let mut blob = build_synthetic_btf("probe_struct", "needle_field", 128);
        blob[0] = 0xff;
        blob[1] = 0xff;
        assert!(resolve_member_offset(&blob, "probe_struct", "needle_field").is_err());
    }

    #[test]
    fn truncated_blob_is_err() {
        assert!(resolve_member_offset(&[0u8; 4], "probe_struct", "needle_field").is_err());
    }
}
