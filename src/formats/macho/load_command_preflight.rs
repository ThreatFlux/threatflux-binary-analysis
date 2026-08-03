use super::super::{MAX_NAME_BYTES, MAX_OWNED_NAME_BYTES, MAX_PARSED_RECORDS};
use crate::{BinaryError, Result};

const MACH_HEADER_32_SIZE: usize = 28;
const MACH_HEADER_64_SIZE: usize = 32;
const LOAD_COMMAND_HEADER_SIZE: usize = 8;
const SEGMENT_COMMAND_32_SIZE: usize = 56;
const SEGMENT_COMMAND_64_SIZE: usize = 72;
const SECTION_32_SIZE: usize = 68;
const SECTION_64_SIZE: usize = 80;
const ENTRY_POINT_COMMAND_SIZE: usize = 24;
const DYLIB_COMMAND_SIZE: usize = 24;
const RPATH_COMMAND_SIZE: usize = 12;
const SYMTAB_COMMAND_SIZE: usize = 24;
const NLIST_32_SIZE: usize = 12;
const NLIST_64_SIZE: usize = 16;

const LC_SEGMENT: u32 = 0x01;
const LC_SYMTAB: u32 = 0x02;
const LC_LOAD_DYLIB: u32 = 0x0c;
const LC_ID_DYLIB: u32 = 0x0d;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_SEGMENT_64: u32 = 0x19;
const LC_RPATH: u32 = 0x8000_001c;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_MAIN: u32 = 0x8000_0028;
const TEXT_SEGMENT_PREFIX: &[u8; 7] = b"__TEXT\0";

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
struct SegmentLayout {
    segment_size: usize,
    section_size: usize,
    count_offset: usize,
    context: &'static str,
}

/// Validate raw load-command operands before Goblin performs host-sized
/// arithmetic or translates `LC_MAIN::entryoff` into a virtual address.
///
/// Goblin 0.10 uses unchecked additions for dylib/rpath strings and nlist
/// string indexes, and unchecked `__TEXT.vmaddr - __TEXT.fileoff + entryoff`
/// arithmetic. This preflight runs before that parser so malformed input
/// cannot panic in debug builds or wrap in release builds, including on 32-bit
/// hosts.
pub(super) fn validate(data: &[u8]) -> Result<()> {
    let magic = data
        .get(..4)
        .ok_or_else(|| BinaryError::invalid_data("Truncated Mach-O header"))?;
    let (byte_order, header_size, nlist_size) = match magic {
        [0xce, 0xfa, 0xed, 0xfe] => (ByteOrder::Little, MACH_HEADER_32_SIZE, NLIST_32_SIZE),
        [0xcf, 0xfa, 0xed, 0xfe] => (ByteOrder::Little, MACH_HEADER_64_SIZE, NLIST_64_SIZE),
        [0xfe, 0xed, 0xfa, 0xce] => (ByteOrder::Big, MACH_HEADER_32_SIZE, NLIST_32_SIZE),
        [0xfe, 0xed, 0xfa, 0xcf] => (ByteOrder::Big, MACH_HEADER_64_SIZE, NLIST_64_SIZE),
        _ => return Err(BinaryError::invalid_data("Invalid thin Mach-O magic")),
    };

    if data.len() < header_size {
        return Err(BinaryError::invalid_data(format!(
            "Truncated Mach-O header (expected at least {header_size} bytes)"
        )));
    }

    let command_count = usize::try_from(read_u32(data, 16, byte_order, "Mach-O ncmds")?)
        .map_err(|_| BinaryError::invalid_data("Mach-O ncmds exceeds usize"))?;
    let command_bytes = usize::try_from(read_u32(data, 20, byte_order, "Mach-O sizeofcmds")?)
        .map_err(|_| BinaryError::invalid_data("Mach-O sizeofcmds exceeds usize"))?;
    let commands_end = header_size
        .checked_add(command_bytes)
        .ok_or_else(|| BinaryError::invalid_data("Mach-O load-command range overflows usize"))?;
    if commands_end > data.len() {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O load-command range {header_size}..{commands_end} exceeds the {}-byte file",
            data.len()
        )));
    }
    if command_count > command_bytes / LOAD_COMMAND_HEADER_SIZE {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O declares {command_count} load commands in only {command_bytes} bytes"
        )));
    }
    if command_count > MAX_PARSED_RECORDS {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O declares {command_count} load commands; limit is {MAX_PARSED_RECORDS}"
        )));
    }

    let mut cursor = header_size;
    let mut first_text_segment = None;
    let mut first_entry_offset = None;
    let mut last_symtab = None;
    let mut section_count = 0_usize;

    for _ in 0..command_count {
        let command_header_end = cursor
            .checked_add(LOAD_COMMAND_HEADER_SIZE)
            .ok_or_else(|| {
                BinaryError::invalid_data("Mach-O load-command header range overflows usize")
            })?;
        if command_header_end > commands_end {
            return Err(BinaryError::invalid_data(
                "Mach-O load-command header exceeds sizeofcmds",
            ));
        }

        let command = read_u32(data, cursor, byte_order, "Mach-O load-command kind")?;
        let command_size = usize::try_from(read_u32(
            data,
            cursor + 4,
            byte_order,
            "Mach-O load-command size",
        )?)
        .map_err(|_| BinaryError::invalid_data("Mach-O load-command size exceeds usize"))?;
        if command_size < LOAD_COMMAND_HEADER_SIZE {
            return Err(BinaryError::invalid_data(format!(
                "Mach-O load command has invalid size {command_size}"
            )));
        }
        let command_end = cursor.checked_add(command_size).ok_or_else(|| {
            BinaryError::invalid_data("Mach-O load-command range overflows usize")
        })?;
        if command_end > commands_end {
            return Err(BinaryError::invalid_data(
                "Mach-O load command exceeds sizeofcmds",
            ));
        }

        match command {
            LC_SEGMENT => {
                validate_segment_sections(
                    data,
                    cursor,
                    command_size,
                    byte_order,
                    SegmentLayout {
                        segment_size: SEGMENT_COMMAND_32_SIZE,
                        section_size: SECTION_32_SIZE,
                        count_offset: 48,
                        context: "LC_SEGMENT",
                    },
                    &mut section_count,
                )?;
                if first_text_segment.is_none() && is_text_segment(data, cursor)? {
                    first_text_segment = Some((
                        u64::from(read_u32(
                            data,
                            cursor + 24,
                            byte_order,
                            "LC_SEGMENT vmaddr",
                        )?),
                        u64::from(read_u32(
                            data,
                            cursor + 32,
                            byte_order,
                            "LC_SEGMENT fileoff",
                        )?),
                    ));
                }
            }
            LC_SEGMENT_64 => {
                validate_segment_sections(
                    data,
                    cursor,
                    command_size,
                    byte_order,
                    SegmentLayout {
                        segment_size: SEGMENT_COMMAND_64_SIZE,
                        section_size: SECTION_64_SIZE,
                        count_offset: 64,
                        context: "LC_SEGMENT_64",
                    },
                    &mut section_count,
                )?;
                if first_text_segment.is_none() && is_text_segment(data, cursor)? {
                    first_text_segment = Some((
                        read_u64(data, cursor + 24, byte_order, "LC_SEGMENT_64 vmaddr")?,
                        read_u64(data, cursor + 40, byte_order, "LC_SEGMENT_64 fileoff")?,
                    ));
                }
            }
            LC_MAIN if first_entry_offset.is_none() => {
                ensure_command_size(command_size, ENTRY_POINT_COMMAND_SIZE, "LC_MAIN")?;
                first_entry_offset =
                    Some(read_u64(data, cursor + 8, byte_order, "LC_MAIN entryoff")?);
            }
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
            | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => validate_command_string(
                data,
                cursor,
                command_size,
                byte_order,
                DYLIB_COMMAND_SIZE,
                "dylib name",
            )?,
            LC_RPATH => validate_command_string(
                data,
                cursor,
                command_size,
                byte_order,
                RPATH_COMMAND_SIZE,
                "rpath",
            )?,
            LC_SYMTAB => {
                ensure_command_size(command_size, SYMTAB_COMMAND_SIZE, "LC_SYMTAB")?;
                // Goblin replaces its symbol view for each LC_SYMTAB command,
                // so only the final table is iterated after load-command parsing.
                last_symtab = Some(cursor);
            }
            _ => {}
        }

        cursor = command_end;
    }

    if let Some(symtab_offset) = last_symtab {
        validate_symtab(data, symtab_offset, byte_order, nlist_size)?;
    }

    if let Some(entry_offset) = first_entry_offset {
        let (vmaddr, fileoff) = first_text_segment
            .ok_or_else(|| BinaryError::invalid_data("Mach-O LC_MAIN has no __TEXT segment"))?;
        let image_base = vmaddr.checked_sub(fileoff).ok_or_else(|| {
            BinaryError::invalid_data(format!(
                "Mach-O __TEXT vmaddr {vmaddr:#x} is below fileoff {fileoff:#x}"
            ))
        })?;
        image_base.checked_add(entry_offset).ok_or_else(|| {
            BinaryError::invalid_data(format!(
                "Mach-O LC_MAIN address {image_base:#x} + {entry_offset:#x} overflows u64"
            ))
        })?;
    }

    Ok(())
}

fn validate_segment_sections(
    data: &[u8],
    command_offset: usize,
    command_size: usize,
    byte_order: ByteOrder,
    layout: SegmentLayout,
    total_sections: &mut usize,
) -> Result<()> {
    ensure_command_size(command_size, layout.segment_size, layout.context)?;
    let count = usize::try_from(read_u32(
        data,
        command_offset + layout.count_offset,
        byte_order,
        &format!("{} nsects", layout.context),
    )?)
    .map_err(|_| BinaryError::invalid_data(format!("{} nsects exceeds usize", layout.context)))?;
    let next_total = total_sections
        .checked_add(count)
        .ok_or_else(|| BinaryError::invalid_data("Mach-O section count overflows usize"))?;
    if next_total > MAX_PARSED_RECORDS {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O segments declare {next_total} sections; limit is {MAX_PARSED_RECORDS}"
        )));
    }

    let required_size = count
        .checked_mul(layout.section_size)
        .and_then(|size| layout.segment_size.checked_add(size))
        .ok_or_else(|| {
            BinaryError::invalid_data(format!("{} section span overflows", layout.context))
        })?;
    if required_size > command_size {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O {} needs {required_size} bytes for {count} sections but its command size is {command_size}",
            layout.context
        )));
    }
    *total_sections = next_total;
    Ok(())
}

fn validate_command_string(
    data: &[u8],
    command_offset: usize,
    command_size: usize,
    byte_order: ByteOrder,
    minimum_offset: usize,
    context: &str,
) -> Result<()> {
    ensure_command_size(command_size, minimum_offset, context)?;
    let relative_u32 = read_u32(
        data,
        command_offset + 8,
        byte_order,
        &format!("Mach-O {context} offset"),
    )?;
    let relative = usize::try_from(relative_u32)
        .map_err(|_| BinaryError::invalid_data(format!("Mach-O {context} offset exceeds usize")))?;
    if relative < minimum_offset || relative >= command_size {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O {context} offset {relative} is outside its {command_size}-byte load command"
        )));
    }

    let absolute = checked_host_add(
        u64::try_from(command_offset)
            .map_err(|_| BinaryError::invalid_data("Mach-O command offset exceeds u64"))?,
        u64::from(relative_u32),
        host_usize_max(),
        &format!("Mach-O {context} address"),
    )?;
    let absolute = usize::try_from(absolute).map_err(|_| {
        BinaryError::invalid_data(format!("Mach-O {context} address exceeds usize"))
    })?;
    let command_end = command_offset.checked_add(command_size).ok_or_else(|| {
        BinaryError::invalid_data("Mach-O load-command string range overflows usize")
    })?;
    let encoded = data.get(absolute..command_end).ok_or_else(|| {
        BinaryError::invalid_data(format!("Mach-O {context} range exceeds the file"))
    })?;
    let terminator = encoded.iter().position(|byte| *byte == 0).ok_or_else(|| {
        BinaryError::invalid_data(format!(
            "Mach-O {context} is not NUL-terminated in its command"
        ))
    })?;
    std::str::from_utf8(&encoded[..terminator])
        .map_err(|_| BinaryError::invalid_data(format!("Mach-O {context} is not valid UTF-8")))?;
    Ok(())
}

fn validate_symtab(
    data: &[u8],
    command_offset: usize,
    byte_order: ByteOrder,
    nlist_size: usize,
) -> Result<()> {
    let symoff = u64::from(read_u32(
        data,
        command_offset + 8,
        byte_order,
        "LC_SYMTAB symoff",
    )?);
    let symbol_count = u64::from(read_u32(
        data,
        command_offset + 12,
        byte_order,
        "LC_SYMTAB nsyms",
    )?);
    let stroff = u64::from(read_u32(
        data,
        command_offset + 16,
        byte_order,
        "LC_SYMTAB stroff",
    )?);
    let string_size = u64::from(read_u32(
        data,
        command_offset + 20,
        byte_order,
        "LC_SYMTAB strsize",
    )?);
    let maximum_records = u64::try_from(MAX_PARSED_RECORDS)
        .map_err(|_| BinaryError::invalid_data("Mach-O parser record limit exceeds u64"))?;
    if symbol_count > maximum_records {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O symbol table declares {symbol_count} records; limit is {MAX_PARSED_RECORDS}"
        )));
    }

    let host_max = host_usize_max();
    let symbol_end = checked_scaled_end(
        symoff,
        symbol_count,
        u64::try_from(nlist_size)
            .map_err(|_| BinaryError::invalid_data("Mach-O nlist size exceeds u64"))?,
        host_max,
        "Mach-O symbol table",
    )?;
    let string_end = checked_host_add(stroff, string_size, host_max, "Mach-O string table")?;
    let file_size = u64::try_from(data.len())
        .map_err(|_| BinaryError::invalid_data("Mach-O file size exceeds u64"))?;
    if symbol_end > file_size {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O symbol-table end {symbol_end:#x} exceeds the {file_size:#x}-byte file"
        )));
    }
    if string_end > file_size {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O string-table end {string_end:#x} exceeds the {file_size:#x}-byte file"
        )));
    }

    let relative_string_table = stroff.checked_sub(symoff).ok_or_else(|| {
        BinaryError::invalid_data(format!(
            "Mach-O string-table offset {stroff:#x} is below symbol-table offset {symoff:#x}"
        ))
    })?;
    let symoff = usize::try_from(symoff)
        .map_err(|_| BinaryError::invalid_data("Mach-O symbol-table offset exceeds usize"))?;
    let string_end = usize::try_from(string_end)
        .map_err(|_| BinaryError::invalid_data("Mach-O string-table end exceeds usize"))?;
    let symbol_count = usize::try_from(symbol_count)
        .map_err(|_| BinaryError::invalid_data("Mach-O symbol count exceeds usize"))?;
    let mut owned_name_bytes = 0_usize;

    for index in 0..symbol_count {
        let record_offset = index
            .checked_mul(nlist_size)
            .and_then(|relative| symoff.checked_add(relative))
            .ok_or_else(|| {
                BinaryError::invalid_data("Mach-O nlist record offset overflows usize")
            })?;
        let string_index = read_u32(data, record_offset, byte_order, "Mach-O nlist string index")?;
        if u64::from(string_index) >= string_size {
            return Err(BinaryError::invalid_data(format!(
                "Mach-O nlist string index {string_index:#x} is outside the {string_size:#x}-byte string table"
            )));
        }

        // Goblin truncates the input at symoff, then adds this relative string
        // table offset and n_strx as usize values while iterating symbols.
        let relative_name = checked_host_add(
            relative_string_table,
            u64::from(string_index),
            host_max,
            "Mach-O nlist relative string offset",
        )?;
        let absolute_name = checked_host_add(
            u64::try_from(symoff)
                .map_err(|_| BinaryError::invalid_data("Mach-O symbol-table offset exceeds u64"))?,
            relative_name,
            host_max,
            "Mach-O nlist string address",
        )?;
        let absolute_name = usize::try_from(absolute_name)
            .map_err(|_| BinaryError::invalid_data("Mach-O nlist string address exceeds usize"))?;
        let remaining = data.get(absolute_name..string_end).ok_or_else(|| {
            BinaryError::invalid_data("Mach-O nlist string index exceeds its string table")
        })?;
        let search_length = remaining.len().min(MAX_NAME_BYTES.saturating_add(1));
        let Some(name_length) = remaining[..search_length]
            .iter()
            .position(|byte| *byte == 0)
        else {
            if remaining.len() > MAX_NAME_BYTES {
                return Err(BinaryError::invalid_data(format!(
                    "Mach-O symbol name exceeds the per-name limit of {MAX_NAME_BYTES} bytes"
                )));
            }
            return Err(BinaryError::invalid_data(
                "Mach-O symbol name is not NUL-terminated in its string table",
            ));
        };
        std::str::from_utf8(&remaining[..name_length])
            .map_err(|_| BinaryError::invalid_data("Mach-O symbol name is not valid UTF-8"))?;
        if name_length != 0 {
            owned_name_bytes = owned_name_bytes.checked_add(name_length).ok_or_else(|| {
                BinaryError::invalid_data("Mach-O owned symbol-name byte count overflows usize")
            })?;
            if owned_name_bytes > MAX_OWNED_NAME_BYTES {
                return Err(BinaryError::invalid_data(format!(
                    "Mach-O symbol names exceed the aggregate limit of {MAX_OWNED_NAME_BYTES} bytes"
                )));
            }
        }
    }

    Ok(())
}

fn host_usize_max() -> u64 {
    u64::try_from(usize::MAX).unwrap_or(u64::MAX)
}

fn checked_host_add(left: u64, right: u64, host_max: u64, context: &str) -> Result<u64> {
    let value = left
        .checked_add(right)
        .ok_or_else(|| BinaryError::invalid_data(format!("{context} addition overflows u64")))?;
    if value > host_max {
        return Err(BinaryError::invalid_data(format!(
            "{context} {left:#x} + {right:#x} exceeds host usize"
        )));
    }
    Ok(value)
}

fn checked_scaled_end(
    start: u64,
    count: u64,
    item_size: u64,
    host_max: u64,
    context: &str,
) -> Result<u64> {
    let byte_length = count
        .checked_mul(item_size)
        .ok_or_else(|| BinaryError::invalid_data(format!("{context} byte length overflows u64")))?;
    checked_host_add(start, byte_length, host_max, context)
}

fn ensure_command_size(actual: usize, minimum: usize, command: &str) -> Result<()> {
    if actual < minimum {
        return Err(BinaryError::invalid_data(format!(
            "Mach-O {command} size {actual} is smaller than {minimum}"
        )));
    }
    Ok(())
}

fn is_text_segment(data: &[u8], command_offset: usize) -> Result<bool> {
    let name_start = command_offset
        .checked_add(8)
        .ok_or_else(|| BinaryError::invalid_data("Mach-O segment-name offset overflows usize"))?;
    let name_end = name_start
        .checked_add(TEXT_SEGMENT_PREFIX.len())
        .ok_or_else(|| BinaryError::invalid_data("Mach-O segment-name range overflows usize"))?;
    Ok(data.get(name_start..name_end) == Some(TEXT_SEGMENT_PREFIX))
}

fn read_u32(data: &[u8], offset: usize, byte_order: ByteOrder, context: &str) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| BinaryError::invalid_data(format!("Truncated {context}")))?;
    Ok(match byte_order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    })
}

fn read_u64(data: &[u8], offset: usize, byte_order: ByteOrder, context: &str) -> Result<u64> {
    let bytes: [u8; 8] = data
        .get(offset..offset.saturating_add(8))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| BinaryError::invalid_data(format!("Truncated {context}")))?;
    Ok(match byte_order {
        ByteOrder::Little => u64::from_le_bytes(bytes),
        ByteOrder::Big => u64::from_be_bytes(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BinaryFormatParser, formats::macho::MachOParser};

    fn macho64_header(command_bytes: usize, command_count: u32) -> Vec<u8> {
        let mut data = vec![0_u8; MACH_HEADER_64_SIZE + command_bytes];
        data[..4].copy_from_slice(&goblin::mach::header::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        data[8..12].copy_from_slice(&3_u32.to_le_bytes());
        data[12..16].copy_from_slice(&2_u32.to_le_bytes());
        data[16..20].copy_from_slice(&command_count.to_le_bytes());
        data[20..24].copy_from_slice(
            &u32::try_from(command_bytes)
                .expect("test command bytes fit u32")
                .to_le_bytes(),
        );
        data
    }

    fn macho64_with_main(vmaddr: u64, fileoff: u64, entryoff: u64) -> Vec<u8> {
        const HEADER_SIZE: usize = MACH_HEADER_64_SIZE;
        const COMMAND_BYTES: usize = SEGMENT_COMMAND_64_SIZE + ENTRY_POINT_COMMAND_SIZE;

        let mut data = macho64_header(COMMAND_BYTES, 2);

        let segment = HEADER_SIZE;
        data[segment..segment + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        data[segment + 4..segment + 8]
            .copy_from_slice(&(SEGMENT_COMMAND_64_SIZE as u32).to_le_bytes());
        data[segment + 8..segment + 15].copy_from_slice(TEXT_SEGMENT_PREFIX);
        data[segment + 24..segment + 32].copy_from_slice(&vmaddr.to_le_bytes());
        data[segment + 32..segment + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[segment + 40..segment + 48].copy_from_slice(&fileoff.to_le_bytes());

        let main = segment + SEGMENT_COMMAND_64_SIZE;
        data[main..main + 4].copy_from_slice(&LC_MAIN.to_le_bytes());
        data[main + 4..main + 8].copy_from_slice(&(ENTRY_POINT_COMMAND_SIZE as u32).to_le_bytes());
        data[main + 8..main + 16].copy_from_slice(&entryoff.to_le_bytes());
        data
    }

    fn macho64_with_string_command(command: u32, command_size: usize, offset: u32) -> Vec<u8> {
        let mut data = macho64_header(command_size, 1);
        let start = MACH_HEADER_64_SIZE;
        data[start..start + 4].copy_from_slice(&command.to_le_bytes());
        data[start + 4..start + 8].copy_from_slice(
            &u32::try_from(command_size)
                .expect("test command size fits u32")
                .to_le_bytes(),
        );
        data[start + 8..start + 12].copy_from_slice(&offset.to_le_bytes());
        data
    }

    fn macho64_with_symtab(string_index: u32) -> Vec<u8> {
        const SYMOFF: usize = MACH_HEADER_64_SIZE + SYMTAB_COMMAND_SIZE;
        const STROFF: usize = SYMOFF + NLIST_64_SIZE;
        const STRINGS: &[u8; 3] = b"\0x\0";

        let mut data = macho64_header(SYMTAB_COMMAND_SIZE, 1);
        data.resize(STROFF + STRINGS.len(), 0);
        let command = MACH_HEADER_64_SIZE;
        data[command..command + 4].copy_from_slice(&LC_SYMTAB.to_le_bytes());
        data[command + 4..command + 8].copy_from_slice(&(SYMTAB_COMMAND_SIZE as u32).to_le_bytes());
        data[command + 8..command + 12].copy_from_slice(&(SYMOFF as u32).to_le_bytes());
        data[command + 12..command + 16].copy_from_slice(&1_u32.to_le_bytes());
        data[command + 16..command + 20].copy_from_slice(&(STROFF as u32).to_le_bytes());
        data[command + 20..command + 24].copy_from_slice(&(STRINGS.len() as u32).to_le_bytes());
        data[SYMOFF..SYMOFF + 4].copy_from_slice(&string_index.to_le_bytes());
        data[STROFF..].copy_from_slice(STRINGS);
        data
    }

    fn parser_error(data: &[u8]) -> String {
        MachOParser::parse(data)
            .err()
            .expect("malformed Mach-O data must be rejected")
            .to_string()
    }

    #[test]
    fn rejects_text_base_underflow_before_goblin_parse() {
        let data = macho64_with_main(0, 1, 0);
        assert!(parser_error(&data).contains("vmaddr 0x0 is below fileoff 0x1"));
    }

    #[test]
    fn rejects_load_command_count_before_goblin_allocation() {
        let count = MAX_PARSED_RECORDS + 1;
        let data = macho64_header(count * LOAD_COMMAND_HEADER_SIZE, count as u32);

        let error = validate(&data).unwrap_err().to_string();

        assert!(error.contains("load commands"));
        assert!(error.contains(&MAX_PARSED_RECORDS.to_string()));
    }

    #[test]
    fn rejects_segment_section_count_before_goblin_materialization() {
        let mut data = macho64_header(SEGMENT_COMMAND_64_SIZE, 1);
        let command = MACH_HEADER_64_SIZE;
        data[command..command + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        data[command + 4..command + 8]
            .copy_from_slice(&(SEGMENT_COMMAND_64_SIZE as u32).to_le_bytes());
        data[command + 64..command + 68]
            .copy_from_slice(&((MAX_PARSED_RECORDS as u32) + 1).to_le_bytes());

        let error = validate(&data).unwrap_err().to_string();

        assert!(error.contains("sections"));
        assert!(error.contains(&MAX_PARSED_RECORDS.to_string()));
    }

    #[test]
    fn rejects_lc_main_address_overflow_before_goblin_parse() {
        let data = macho64_with_main(u64::MAX, 0, 1);
        assert!(parser_error(&data).contains("overflows u64"));
    }

    #[test]
    fn accepts_bounded_lc_main_address() {
        let data = macho64_with_main(0x1000, 0, 0x100);
        validate(&data).expect("bounded LC_MAIN address must pass preflight");
        MachOParser::parse(&data).expect("bounded LC_MAIN Mach-O must parse");
    }

    #[test]
    fn rejects_out_of_command_dylib_and_rpath_offsets() {
        for command in [
            LC_LOAD_DYLIB,
            LC_ID_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_REEXPORT_DYLIB,
            LC_LAZY_LOAD_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
        ] {
            let data = macho64_with_string_command(command, DYLIB_COMMAND_SIZE, u32::MAX);
            assert!(parser_error(&data).contains("dylib name offset"));
        }

        let data = macho64_with_string_command(LC_RPATH, RPATH_COMMAND_SIZE, u32::MAX);
        assert!(parser_error(&data).contains("rpath offset"));
    }

    #[test]
    fn rejects_unterminated_load_command_string() {
        let mut data = macho64_with_string_command(LC_LOAD_DYLIB, 28, DYLIB_COMMAND_SIZE as u32);
        data[MACH_HEADER_64_SIZE + DYLIB_COMMAND_SIZE..].fill(b'x');
        assert!(parser_error(&data).contains("not NUL-terminated in its command"));
    }

    #[test]
    fn accepts_bounded_dylib_string() {
        let mut data = macho64_with_string_command(LC_LOAD_DYLIB, 28, DYLIB_COMMAND_SIZE as u32);
        data[MACH_HEADER_64_SIZE + DYLIB_COMMAND_SIZE..].copy_from_slice(b"x\0\0\0");
        validate(&data).expect("bounded dylib string must pass preflight");
        MachOParser::parse(&data).expect("bounded dylib Mach-O must parse");
    }

    #[test]
    fn rejects_out_of_range_nlist_string_index() {
        let data = macho64_with_symtab(u32::MAX);
        assert!(parser_error(&data).contains("nlist string index"));
    }

    #[test]
    fn accepts_bounded_symtab_and_nlist_string() {
        let data = macho64_with_symtab(1);
        validate(&data).expect("bounded Mach-O symbol table must pass preflight");
        MachOParser::parse(&data).expect("bounded symbol-table Mach-O must parse");
    }

    #[test]
    fn simulated_32_bit_host_rejects_offset_addition_wrap() {
        let host_max = u64::from(u32::MAX);
        let error = checked_host_add(host_max - 1, 2, host_max, "test offset")
            .expect_err("32-bit host-sized addition must reject overflow")
            .to_string();
        assert!(error.contains("exceeds host usize"));
    }

    #[test]
    fn simulated_32_bit_host_rejects_nlist_table_span() {
        let host_max = u64::from(u32::MAX);
        let error = checked_scaled_end(
            0x1000,
            u64::from(u32::MAX),
            u64::try_from(NLIST_64_SIZE).expect("nlist size fits u64"),
            host_max,
            "test nlist table",
        )
        .expect_err("32-bit nlist table arithmetic must reject overflow")
        .to_string();
        assert!(error.contains("exceeds host usize"));
    }
}
