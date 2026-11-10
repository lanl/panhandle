//! Minimal reader for the running kernel's raw BTF (`/sys/kernel/btf/vmlinux`), just
//! enough to find one struct member's byte offset.
//!
//! Rust eBPF code can't use CO-RE field relocations (aya-ebpf has no equivalent of C's
//! `preserve_access_index`), so any kernel struct field the eBPF side touches would
//! otherwise be compiled in at one kernel's layout - which breaks when that layout
//! changes (e.g. `struct file` was reordered around 6.12). Instead, userspace looks the
//! offset up here and injects it as a load-time global (`EbpfLoader::override_global`);
//! the global lives in frozen `.rodata`, so the verifier treats it as a constant. aya
//! parses BTF itself but keeps member offsets private, hence this small reader.

/// Path to the running kernel's BTF.
pub const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

const BTF_MAGIC: u16 = 0xEB9F;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
// Anonymous struct/union nesting is shallow in practice; this just bounds malformed input.
const MAX_DEPTH: u32 = 16;

fn u32_at(buf: &[u8], off: usize) -> Result<u32, String> {
    buf.get(off..off + 4)
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "truncated BTF".to_string())
}

struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    // byte position of each type's 12-byte header, indexed by type id - 1
    headers: Vec<usize>,
}

impl<'a> Btf<'a> {
    fn parse(btf: &'a [u8]) -> Result<Self, String> {
        if btf.len() < 24 {
            return Err("truncated BTF header".to_string());
        }
        let magic = u16::from_ne_bytes([btf[0], btf[1]]);
        if magic != BTF_MAGIC {
            return Err(format!("not native-endian BTF (magic {magic:#06x})"));
        }
        let hdr_len = u32_at(btf, 4)? as usize;
        let (type_off, type_len) = (u32_at(btf, 8)? as usize, u32_at(btf, 12)? as usize);
        let (str_off, str_len) = (u32_at(btf, 16)? as usize, u32_at(btf, 20)? as usize);
        let types = btf
            .get(hdr_len + type_off..hdr_len + type_off + type_len)
            .ok_or("truncated BTF type section")?;
        let strings = btf
            .get(hdr_len + str_off..hdr_len + str_off + str_len)
            .ok_or("truncated BTF string section")?;

        let mut headers = Vec::new();
        let mut pos = 0;
        while pos < types.len() {
            headers.push(pos);
            let info = u32_at(types, pos + 4)?;
            let vlen = (info & 0xffff) as usize;
            // Size of the kind-specific data following each 12-byte btf_type header.
            pos += 12
                + match (info >> 24) & 0x1f {
                    1 | 14 | 17 => 4,          // INT, VAR, DECL_TAG
                    3 => 12,                   // ARRAY
                    4 | 5 => 12 * vlen,        // STRUCT, UNION: btf_member each
                    6 | 13 => 8 * vlen,        // ENUM, FUNC_PROTO
                    15 | 19 => 12 * vlen,      // DATASEC, ENUM64
                    2 | 7..=12 | 16 | 18 => 0, // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG
                    kind => return Err(format!("unknown BTF kind {kind}")),
                };
        }
        Ok(Self {
            types,
            strings,
            headers,
        })
    }

    fn name(&self, off: u32) -> &[u8] {
        self.strings
            .get(off as usize..)
            .and_then(|s| s.split(|&b| b == 0).next())
            .unwrap_or(&[])
    }

    // (name_off, info, size_or_type, header position) for a type id
    fn header(&self, id: u32) -> Result<(u32, u32, u32, usize), String> {
        let pos = *id
            .checked_sub(1)
            .and_then(|i| self.headers.get(i as usize))
            .ok_or_else(|| format!("BTF type id {id} out of range"))?;
        Ok((
            u32_at(self.types, pos)?,
            u32_at(self.types, pos + 4)?,
            u32_at(self.types, pos + 8)?,
            pos,
        ))
    }

    // Follow TYPEDEF/VOLATILE/CONST/RESTRICT/TYPE_TAG to the underlying type.
    fn resolve(&self, mut id: u32) -> Result<u32, String> {
        for _ in 0..MAX_DEPTH {
            let (_, info, next, _) = self.header(id)?;
            match (info >> 24) & 0x1f {
                8..=11 | 18 => id = next,
                _ => return Ok(id),
            }
        }
        Err("BTF modifier chain too deep".to_string())
    }

    // Bit offset of `member` in struct/union `id`, looking through anonymous
    // struct/union members (e.g. `union { const struct path f_path; ... }`).
    fn member_bits(&self, id: u32, member: &[u8], depth: u32) -> Result<Option<u32>, String> {
        if depth > MAX_DEPTH {
            return Err("BTF struct nesting too deep".to_string());
        }
        let (_, info, _, pos) = self.header(id)?;
        let kind = (info >> 24) & 0x1f;
        if kind != KIND_STRUCT && kind != KIND_UNION {
            return Ok(None);
        }
        let kind_flag = info >> 31 == 1;
        for i in 0..(info & 0xffff) as usize {
            let m = pos + 12 + 12 * i;
            let (name_off, member_type) = (u32_at(self.types, m)?, u32_at(self.types, m + 4)?);
            // With kind_flag set, the low 24 bits are the bit offset and the high 8 bits
            // the bitfield size; otherwise the whole value is the bit offset.
            let raw = u32_at(self.types, m + 8)?;
            let bits = if kind_flag { raw & 0x00ff_ffff } else { raw };
            if self.name(name_off) == member {
                return Ok(Some(bits));
            }
            if name_off == 0 {
                let inner = self.resolve(member_type)?;
                if let Some(inner_bits) = self.member_bits(inner, member, depth + 1)? {
                    return Ok(Some(bits + inner_bits));
                }
            }
        }
        Ok(None)
    }
}

/// Byte offset of `member_name` within `struct struct_name`, read from a raw BTF blob.
pub fn struct_member_offset(
    btf: &[u8],
    struct_name: &str,
    member_name: &str,
) -> Result<u32, String> {
    let btf = Btf::parse(btf)?;
    for id in 1..=btf.headers.len() as u32 {
        let (name_off, info, _, _) = btf.header(id)?;
        if (info >> 24) & 0x1f != KIND_STRUCT || btf.name(name_off) != struct_name.as_bytes() {
            continue;
        }
        let bits = btf
            .member_bits(id, member_name.as_bytes(), 0)?
            .ok_or_else(|| format!("struct {struct_name} has no member {member_name}"))?;
        if !bits.is_multiple_of(8) {
            return Err(format!("{struct_name}.{member_name} is not byte-aligned"));
        }
        return Ok(bits / 8);
    }
    Err(format!("struct {struct_name} not found in BTF"))
}

/// Byte offset of `member_name` within `struct struct_name` on the running kernel.
pub fn kernel_struct_member_offset(struct_name: &str, member_name: &str) -> Result<u32, String> {
    let btf = std::fs::read(KERNEL_BTF_PATH)
        .map_err(|e| format!("could not read kernel BTF at {KERNEL_BTF_PATH}: {e}"))?;
    struct_member_offset(&btf, struct_name, member_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a raw BTF blob from (name, info, size_or_type, extra-data) type records.
    fn btf_blob(types: &[(u32, u32, u32, Vec<u32>)], strings: &[u8]) -> Vec<u8> {
        let mut type_sec = Vec::new();
        for (name_off, info, size, extra) in types {
            for v in [*name_off, *info, *size].iter().chain(extra.iter()) {
                type_sec.extend_from_slice(&v.to_ne_bytes());
            }
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_ne_bytes());
        blob.extend_from_slice(&[1, 0]); // version, flags
        for v in [
            24u32,
            0,
            type_sec.len() as u32,
            type_sec.len() as u32,
            strings.len() as u32,
        ] {
            blob.extend_from_slice(&v.to_ne_bytes());
        }
        blob.extend_from_slice(&type_sec);
        blob.extend_from_slice(strings);
        blob
    }

    // strings: 0 "", 1 "int", 5 "file", 10 "f_lock", 17 "f_path", 24 "flags"
    const STRINGS: &[u8] = b"\0int\0file\0f_lock\0f_path\0flags\0";

    #[test]
    fn finds_member_after_skipping_other_kinds() {
        let types = [
            (1, 1 << 24, 4, vec![32]),                          // INT "int"
            (0, 3 << 24, 0, vec![1, 1, 4]),                     // ARRAY
            (0, (6 << 24) | 1, 4, vec![24, 0]),                 // ENUM, 1 value
            (5, (4 << 24) | 2, 64, vec![10, 1, 0, 17, 1, 128]), // STRUCT file
        ];
        let blob = btf_blob(&types, STRINGS);
        assert_eq!(struct_member_offset(&blob, "file", "f_path"), Ok(16));
        assert_eq!(struct_member_offset(&blob, "file", "f_lock"), Ok(0));
    }

    #[test]
    fn finds_member_inside_anonymous_union() {
        // newer kernels: struct file { ...; union { const struct path f_path; ... }; }
        let types = [
            (1, 1 << 24, 4, vec![32]),                         // 1: INT "int"
            (0, 10 << 24, 1, vec![]),                          // 2: CONST -> int
            (0, (5 << 24) | 1, 16, vec![17, 2, 0]),            // 3: anon UNION { f_path @0 }
            (5, (4 << 24) | 2, 64, vec![10, 1, 0, 0, 3, 512]), // 4: STRUCT file, union @64B
        ];
        let blob = btf_blob(&types, STRINGS);
        assert_eq!(struct_member_offset(&blob, "file", "f_path"), Ok(64));
    }

    #[test]
    fn kind_flag_uses_low_24_bits_as_bit_offset() {
        // kind_flag set: member offset = (bitfield size 0 << 24) | bit offset 384
        let types = [(5, (1 << 31) | (4 << 24) | 1, 64, vec![17, 1, 384])];
        let blob = btf_blob(&types, STRINGS);
        assert_eq!(struct_member_offset(&blob, "file", "f_path"), Ok(48));
    }

    #[test]
    fn reports_missing_struct_member_and_unaligned_bitfield() {
        let types = [(5, (4 << 24) | 1, 64, vec![24, 1, 3])];
        let blob = btf_blob(&types, STRINGS);
        assert!(
            struct_member_offset(&blob, "file", "f_path")
                .unwrap_err()
                .contains("no member")
        );
        assert!(
            struct_member_offset(&blob, "file", "flags")
                .unwrap_err()
                .contains("byte-aligned")
        );
        assert!(
            struct_member_offset(&blob, "inode", "i_mode")
                .unwrap_err()
                .contains("not found")
        );
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        assert!(struct_member_offset(&[0u8; 24], "file", "f_path").is_err());
        assert!(struct_member_offset(&[0u8; 8], "file", "f_path").is_err());
    }

    // Against the real kernel BTF when available (skipped otherwise, e.g. in containers).
    #[test]
    fn kernel_file_f_path_offset_is_plausible() {
        if !std::path::Path::new(KERNEL_BTF_PATH).exists() {
            return;
        }
        let off = kernel_struct_member_offset("file", "f_path").expect("struct file.f_path");
        assert!(off.is_multiple_of(8) && off < 512, "implausible f_path offset {off}");
    }
}
