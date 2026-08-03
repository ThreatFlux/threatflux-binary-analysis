//! Resource-safe validation for Goblin's dyld bind and export helpers.
//!
//! Goblin materializes bind records and recursively walks export tries. Validate
//! attacker-controlled streams before invoking those helpers so malformed input
//! cannot amplify into unbounded allocation, unchecked indexing, or recursion.
//! The gate is deliberately fail-closed: weak-bind streams are validated even
//! though Goblin currently ignores them, and unknown opcodes or non-canonical
//! LEB128 encodings are rejected rather than delegated to permissive behavior.

use crate::{
    BinaryError, Result,
    formats::{MAX_NAME_BYTES, MAX_OWNED_NAME_BYTES, MAX_PARSED_RECORDS},
};
use goblin::mach::{
    MachO,
    bind_opcodes::{
        BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
        BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_MASK,
        BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
        BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
        BIND_OPCODE_SET_TYPE_IMM, BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION,
        BIND_SYMBOL_FLAGS_WEAK_IMPORT, BIND_TYPE_POINTER, BIND_TYPE_TEXT_ABSOLUTE32,
        BIND_TYPE_TEXT_PCREL32,
    },
    exports::{
        EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, EXPORT_SYMBOL_FLAGS_KIND_MASK,
        EXPORT_SYMBOL_FLAGS_KIND_REGULAR, EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
        EXPORT_SYMBOL_FLAGS_REEXPORT, EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
    },
    load_command::CommandVariant,
    segment::Segment,
};

const MAX_EXPORT_TRIE_DEPTH: usize = 128;

#[derive(Default)]
struct PreflightStats {
    records: usize,
    owned_name_bytes: usize,
    trie_nodes: usize,
    trie_edges: usize,
}

impl PreflightStats {
    fn add_records(&mut self, count: usize, context: &str) -> Result<()> {
        self.records = self.records.checked_add(count).ok_or_else(|| {
            BinaryError::invalid_data(format!("{context} record count overflows usize"))
        })?;
        if self.records > MAX_PARSED_RECORDS {
            return Err(BinaryError::invalid_data(format!(
                "{context} expands beyond the parser record limit of {MAX_PARSED_RECORDS}"
            )));
        }
        Ok(())
    }

    fn add_owned_name_bytes(&mut self, count: usize, context: &str) -> Result<()> {
        self.owned_name_bytes = self.owned_name_bytes.checked_add(count).ok_or_else(|| {
            BinaryError::invalid_data(format!("{context} name-byte count overflows usize"))
        })?;
        if self.owned_name_bytes > MAX_OWNED_NAME_BYTES {
            return Err(BinaryError::invalid_data(format!(
                "{context} expands names beyond the aggregate limit of {MAX_OWNED_NAME_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn visit_trie_node(&mut self) -> Result<()> {
        self.trie_nodes = self.trie_nodes.checked_add(1).ok_or_else(|| {
            BinaryError::invalid_data("Mach-O export-trie node count overflows usize")
        })?;
        if self.trie_nodes > MAX_PARSED_RECORDS {
            return Err(BinaryError::invalid_data(format!(
                "Mach-O export trie exceeds the node limit of {MAX_PARSED_RECORDS}"
            )));
        }
        Ok(())
    }

    fn add_trie_edges(&mut self, count: usize) -> Result<()> {
        self.trie_edges = self.trie_edges.checked_add(count).ok_or_else(|| {
            BinaryError::invalid_data("Mach-O export-trie edge count overflows usize")
        })?;
        if self.trie_edges > MAX_PARSED_RECORDS {
            return Err(BinaryError::invalid_data(format!(
                "Mach-O export trie exceeds the edge limit of {MAX_PARSED_RECORDS}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct BindState {
    segment_index: usize,
    segment_offset: u64,
    library_ordinal: usize,
    symbol_name_len: Option<usize>,
}

pub(super) fn validate(macho: &MachO<'_>, data: &[u8]) -> Result<()> {
    let mut stats = PreflightStats::default();

    for load_command in &macho.load_commands {
        match &load_command.command {
            CommandVariant::DyldInfo(command) | CommandVariant::DyldInfoOnly(command) => {
                validate_bind_range(
                    data,
                    command.bind_off,
                    command.bind_size,
                    "Mach-O bind stream",
                    macho,
                    &mut stats,
                )?;
                validate_bind_range(
                    data,
                    command.weak_bind_off,
                    command.weak_bind_size,
                    "Mach-O weak-bind stream",
                    macho,
                    &mut stats,
                )?;
                validate_bind_range(
                    data,
                    command.lazy_bind_off,
                    command.lazy_bind_size,
                    "Mach-O lazy-bind stream",
                    macho,
                    &mut stats,
                )?;
                validate_export_range(
                    data,
                    command.export_off,
                    command.export_size,
                    "Mach-O export trie",
                    &macho.libs,
                    &mut stats,
                )?;
            }
            CommandVariant::DyldExportsTrie(command) => validate_export_range(
                data,
                command.dataoff,
                command.datasize,
                "Mach-O exports-trie command",
                &macho.libs,
                &mut stats,
            )?,
            _ => {}
        }
    }

    Ok(())
}

fn checked_stream_range<'a>(
    data: &'a [u8],
    offset: u32,
    size: u32,
    context: &str,
) -> Result<&'a [u8]> {
    if size == 0 {
        return Ok(&[]);
    }

    let start = usize::try_from(offset)
        .map_err(|_| BinaryError::invalid_data(format!("{context} offset exceeds usize")))?;
    let length = usize::try_from(size)
        .map_err(|_| BinaryError::invalid_data(format!("{context} size exceeds usize")))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| BinaryError::invalid_data(format!("{context} range overflows usize")))?;
    data.get(start..end).ok_or_else(|| {
        BinaryError::invalid_data(format!(
            "{context} range {start}..{end} exceeds the {}-byte file",
            data.len()
        ))
    })
}

fn validate_bind_range(
    data: &[u8],
    offset: u32,
    size: u32,
    context: &str,
    macho: &MachO<'_>,
    stats: &mut PreflightStats,
) -> Result<()> {
    let stream = checked_stream_range(data, offset, size, context)?;
    if stream.is_empty() {
        return Ok(());
    }

    validate_bind_stream(stream, context, macho, stats)
}

fn validate_bind_stream(
    stream: &[u8],
    context: &str,
    macho: &MachO<'_>,
    stats: &mut PreflightStats,
) -> Result<()> {
    let pointer_size = if macho.is_64 { 8_u64 } else { 4_u64 };
    let mut cursor = 0_usize;
    let mut state = BindState::default();

    while cursor < stream.len() {
        let opcode = stream[cursor];
        cursor += 1;
        let operation = opcode & BIND_OPCODE_MASK;
        let immediate = opcode & BIND_IMMEDIATE_MASK;

        match operation {
            BIND_OPCODE_DONE => {
                require_zero_immediate(opcode, immediate, context)?;
                state = BindState::default();
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                state.library_ordinal = usize::from(immediate);
                validate_library_ordinal(state.library_ordinal, macho, context)?;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                require_zero_immediate(opcode, immediate, context)?;
                let ordinal = read_uleb(stream, &mut cursor, context)?;
                if ordinal > u64::from(u8::MAX) {
                    return Err(BinaryError::invalid_data(format!(
                        "{context} library ordinal {ordinal} exceeds Goblin's u8 state"
                    )));
                }
                state.library_ordinal = usize::try_from(ordinal).map_err(|_| {
                    BinaryError::invalid_data(format!("{context} library ordinal exceeds usize"))
                })?;
                validate_library_ordinal(state.library_ordinal, macho, context)?;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if !matches!(immediate, 0 | 0x0d | 0x0e | 0x0f) {
                    return Err(BinaryError::invalid_data(format!(
                        "{context} contains invalid special-library immediate {immediate:#x}"
                    )));
                }
                // Goblin retains its ordinary ordinal for special libraries.
                // Validate that state because Import::new indexes it directly.
                validate_library_ordinal(state.library_ordinal, macho, context)?;
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let allowed_flags =
                    BIND_SYMBOL_FLAGS_WEAK_IMPORT | BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION;
                if immediate & !allowed_flags != 0 {
                    return Err(BinaryError::invalid_data(format!(
                        "{context} contains unsupported symbol flags {immediate:#x}"
                    )));
                }
                let symbol = read_c_string(stream, &mut cursor, stream.len(), context)?;
                if symbol.is_empty() {
                    return Err(BinaryError::invalid_data(format!(
                        "{context} contains an empty symbol name"
                    )));
                }
                state.symbol_name_len = Some(symbol.len());
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                if !matches!(
                    immediate,
                    BIND_TYPE_POINTER | BIND_TYPE_TEXT_ABSOLUTE32 | BIND_TYPE_TEXT_PCREL32
                ) {
                    return Err(BinaryError::invalid_data(format!(
                        "{context} contains invalid bind type {immediate}"
                    )));
                }
            }
            BIND_OPCODE_SET_ADDEND_SLEB => {
                require_zero_immediate(opcode, immediate, context)?;
                read_sleb(stream, &mut cursor, context)?;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                state.segment_index = usize::from(immediate);
                if state.segment_index >= macho.segments.len() {
                    return Err(BinaryError::invalid_data(format!(
                        "{context} segment index {} exceeds {} segments",
                        state.segment_index,
                        macho.segments.len()
                    )));
                }
                state.segment_offset = read_uleb(stream, &mut cursor, context)?;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                require_zero_immediate(opcode, immediate, context)?;
                let increment = read_uleb(stream, &mut cursor, context)?;
                state.segment_offset =
                    state.segment_offset.checked_add(increment).ok_or_else(|| {
                        BinaryError::invalid_data(format!("{context} segment offset overflows u64"))
                    })?;
            }
            BIND_OPCODE_DO_BIND => {
                require_zero_immediate(opcode, immediate, context)?;
                validate_bindings(
                    &state,
                    macho,
                    pointer_size,
                    1,
                    state.segment_offset,
                    stats,
                    context,
                )?;
                state.segment_offset =
                    state
                        .segment_offset
                        .checked_add(pointer_size)
                        .ok_or_else(|| {
                            BinaryError::invalid_data(format!(
                                "{context} segment offset overflows u64"
                            ))
                        })?;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                require_zero_immediate(opcode, immediate, context)?;
                let increment = read_uleb(stream, &mut cursor, context)?;
                validate_bindings(
                    &state,
                    macho,
                    pointer_size,
                    1,
                    state.segment_offset,
                    stats,
                    context,
                )?;
                state.segment_offset = state
                    .segment_offset
                    .checked_add(increment)
                    .and_then(|offset| offset.checked_add(pointer_size))
                    .ok_or_else(|| {
                        BinaryError::invalid_data(format!("{context} segment offset overflows u64"))
                    })?;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                validate_bindings(
                    &state,
                    macho,
                    pointer_size,
                    1,
                    state.segment_offset,
                    stats,
                    context,
                )?;
                let scaled = u64::from(immediate)
                    .checked_mul(pointer_size)
                    .and_then(|value| value.checked_add(pointer_size))
                    .ok_or_else(|| {
                        BinaryError::invalid_data(format!("{context} scaled offset overflows u64"))
                    })?;
                state.segment_offset =
                    state.segment_offset.checked_add(scaled).ok_or_else(|| {
                        BinaryError::invalid_data(format!("{context} segment offset overflows u64"))
                    })?;
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                require_zero_immediate(opcode, immediate, context)?;
                let count = read_uleb(stream, &mut cursor, context)?;
                let skip = read_uleb(stream, &mut cursor, context)?;
                let count = usize::try_from(count).map_err(|_| {
                    BinaryError::invalid_data(format!("{context} bind count exceeds usize"))
                })?;
                let step = skip.checked_add(pointer_size).ok_or_else(|| {
                    BinaryError::invalid_data(format!("{context} bind stride overflows u64"))
                })?;
                let last_offset = if count == 0 {
                    state.segment_offset
                } else {
                    step.checked_mul((count - 1) as u64)
                        .and_then(|delta| state.segment_offset.checked_add(delta))
                        .ok_or_else(|| {
                            BinaryError::invalid_data(format!(
                                "{context} repeated bind offset overflows u64"
                            ))
                        })?
                };
                validate_bindings(
                    &state,
                    macho,
                    pointer_size,
                    count,
                    last_offset,
                    stats,
                    context,
                )?;
                state.segment_offset = step
                    .checked_mul(count as u64)
                    .and_then(|delta| state.segment_offset.checked_add(delta))
                    .ok_or_else(|| {
                        BinaryError::invalid_data(format!(
                            "{context} repeated bind final offset overflows u64"
                        ))
                    })?;
            }
            _ => {
                return Err(BinaryError::invalid_data(format!(
                    "{context} contains unknown bind opcode {opcode:#04x}"
                )));
            }
        }
    }

    Ok(())
}

fn require_zero_immediate(opcode: u8, immediate: u8, context: &str) -> Result<()> {
    if immediate != 0 {
        return Err(BinaryError::invalid_data(format!(
            "{context} opcode {opcode:#04x} has a nonzero reserved immediate"
        )));
    }
    Ok(())
}

fn validate_library_ordinal(ordinal: usize, macho: &MachO<'_>, context: &str) -> Result<()> {
    if ordinal >= macho.libs.len() {
        return Err(BinaryError::invalid_data(format!(
            "{context} library ordinal {ordinal} exceeds {} libraries",
            macho.libs.len()
        )));
    }
    Ok(())
}

fn validate_bindings(
    state: &BindState,
    macho: &MachO<'_>,
    pointer_size: u64,
    count: usize,
    last_offset: u64,
    stats: &mut PreflightStats,
    context: &str,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    stats.add_records(count, context)?;

    let symbol_name_len = state.symbol_name_len.ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} binds before setting a symbol name"))
    })?;
    let segment = macho.segments.get(state.segment_index).ok_or_else(|| {
        BinaryError::invalid_data(format!(
            "{context} segment index {} exceeds {} segments",
            state.segment_index,
            macho.segments.len()
        ))
    })?;
    let library = macho.libs.get(state.library_ordinal).ok_or_else(|| {
        BinaryError::invalid_data(format!(
            "{context} library ordinal {} exceeds {} libraries",
            state.library_ordinal,
            macho.libs.len()
        ))
    })?;

    validate_binding_address(segment, state.segment_offset, pointer_size, context)?;
    validate_binding_address(segment, last_offset, pointer_size, context)?;

    let bytes_per_record = symbol_name_len.checked_add(library.len()).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} owned name length overflows usize"))
    })?;
    let owned_bytes = bytes_per_record.checked_mul(count).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} owned name-byte count overflows usize"))
    })?;
    stats.add_owned_name_bytes(owned_bytes, context)
}

fn validate_binding_address(
    segment: &Segment<'_>,
    offset: u64,
    pointer_size: u64,
    context: &str,
) -> Result<()> {
    let end = offset.checked_add(pointer_size).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} binding range overflows u64"))
    })?;
    if end > segment.vmsize {
        return Err(BinaryError::invalid_data(format!(
            "{context} binding range {offset}..{end} exceeds segment virtual size {}",
            segment.vmsize
        )));
    }
    segment.fileoff.checked_add(offset).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} binding file offset overflows u64"))
    })?;
    segment.vmaddr.checked_add(offset).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} binding address overflows u64"))
    })?;
    Ok(())
}

fn validate_export_range(
    data: &[u8],
    offset: u32,
    size: u32,
    context: &str,
    libraries: &[&str],
    stats: &mut PreflightStats,
) -> Result<()> {
    let stream = checked_stream_range(data, offset, size, context)?;
    if stream.is_empty() {
        return Ok(());
    }

    let mut path = [usize::MAX; MAX_EXPORT_TRIE_DEPTH];
    validate_export_node(stream, 0, 0, 0, &mut path, libraries, stats, context)
}

#[allow(clippy::too_many_arguments)]
fn validate_export_node(
    stream: &[u8],
    node_offset: usize,
    symbol_name_len: usize,
    depth: usize,
    path: &mut [usize; MAX_EXPORT_TRIE_DEPTH],
    libraries: &[&str],
    stats: &mut PreflightStats,
    context: &str,
) -> Result<()> {
    if depth >= MAX_EXPORT_TRIE_DEPTH {
        return Err(BinaryError::invalid_data(format!(
            "{context} exceeds the maximum depth of {MAX_EXPORT_TRIE_DEPTH}"
        )));
    }
    if node_offset >= stream.len() {
        return Err(BinaryError::invalid_data(format!(
            "{context} node offset {node_offset} exceeds its {}-byte range",
            stream.len()
        )));
    }
    if path[..depth].contains(&node_offset) {
        return Err(BinaryError::invalid_data(format!(
            "{context} contains a cycle at node offset {node_offset}"
        )));
    }
    path[depth] = node_offset;
    stats.visit_trie_node()?;

    let mut cursor = node_offset;
    let terminal_size = read_uleb(stream, &mut cursor, context)?;
    let terminal_size = usize::try_from(terminal_size)
        .map_err(|_| BinaryError::invalid_data(format!("{context} terminal size exceeds usize")))?;

    if terminal_size != 0 {
        let terminal_end = cursor.checked_add(terminal_size).ok_or_else(|| {
            BinaryError::invalid_data(format!("{context} terminal range overflows usize"))
        })?;
        if terminal_end > stream.len() {
            return Err(BinaryError::invalid_data(format!(
                "{context} terminal range exceeds its {}-byte stream",
                stream.len()
            )));
        }
        validate_export_terminal(
            stream,
            &mut cursor,
            terminal_end,
            symbol_name_len,
            libraries,
            stats,
            context,
        )?;
        if cursor != terminal_end {
            return Err(BinaryError::invalid_data(format!(
                "{context} terminal payload has {} trailing bytes",
                terminal_end - cursor
            )));
        }
    }

    let child_count = read_uleb(stream, &mut cursor, context)?;
    let child_count = usize::try_from(child_count)
        .map_err(|_| BinaryError::invalid_data(format!("{context} child count exceeds usize")))?;
    stats.add_trie_edges(child_count)?;

    for _ in 0..child_count {
        let edge = read_c_string(stream, &mut cursor, stream.len(), context)?;
        if edge.is_empty() {
            return Err(BinaryError::invalid_data(format!(
                "{context} contains an empty branch label"
            )));
        }
        let child_symbol_len = symbol_name_len.checked_add(edge.len()).ok_or_else(|| {
            BinaryError::invalid_data(format!("{context} symbol length overflows usize"))
        })?;
        if child_symbol_len > MAX_NAME_BYTES {
            return Err(BinaryError::invalid_data(format!(
                "{context} symbol is {child_symbol_len} bytes; limit is {MAX_NAME_BYTES}"
            )));
        }
        stats.add_owned_name_bytes(child_symbol_len, context)?;

        let child_offset = read_uleb(stream, &mut cursor, context)?;
        let child_offset = usize::try_from(child_offset).map_err(|_| {
            BinaryError::invalid_data(format!("{context} child offset exceeds usize"))
        })?;
        validate_export_node(
            stream,
            child_offset,
            child_symbol_len,
            depth + 1,
            path,
            libraries,
            stats,
            context,
        )?;
    }

    Ok(())
}

fn validate_export_terminal(
    stream: &[u8],
    cursor: &mut usize,
    terminal_end: usize,
    symbol_name_len: usize,
    libraries: &[&str],
    stats: &mut PreflightStats,
    context: &str,
) -> Result<()> {
    let flags = read_uleb_bounded(stream, cursor, terminal_end, context)?;
    let kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
    let supports_reexport = matches!(
        kind,
        EXPORT_SYMBOL_FLAGS_KIND_REGULAR
            | EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
            | EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
    );

    if supports_reexport && flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let ordinal = read_uleb_bounded(stream, cursor, terminal_end, context)?;
        let ordinal = usize::try_from(ordinal).map_err(|_| {
            BinaryError::invalid_data(format!("{context} reexport ordinal exceeds usize"))
        })?;
        let library = libraries.get(ordinal).ok_or_else(|| {
            BinaryError::invalid_data(format!(
                "{context} reexport library ordinal {ordinal} exceeds {} libraries",
                libraries.len()
            ))
        })?;
        let target = read_c_string(stream, cursor, terminal_end, context)?;
        let target_len = if target.is_empty() {
            symbol_name_len
        } else {
            target.len()
        };
        let forwarded_len = library
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(target_len))
            .ok_or_else(|| {
                BinaryError::invalid_data(format!("{context} reexport name length overflows usize"))
            })?;
        if forwarded_len > MAX_NAME_BYTES {
            return Err(BinaryError::invalid_data(format!(
                "{context} reexport name is {forwarded_len} bytes; limit is {MAX_NAME_BYTES}"
            )));
        }
        stats.add_owned_name_bytes(forwarded_len, context)?;
    } else if kind == EXPORT_SYMBOL_FLAGS_KIND_REGULAR
        && flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0
    {
        read_uleb_bounded(stream, cursor, terminal_end, context)?;
        read_uleb_bounded(stream, cursor, terminal_end, context)?;
    } else {
        read_uleb_bounded(stream, cursor, terminal_end, context)?;
    }

    stats.add_records(1, context)?;
    stats.add_owned_name_bytes(symbol_name_len, context)
}

fn read_uleb(stream: &[u8], cursor: &mut usize, context: &str) -> Result<u64> {
    read_uleb_bounded(stream, cursor, stream.len(), context)
}

fn read_uleb_bounded(stream: &[u8], cursor: &mut usize, end: usize, context: &str) -> Result<u64> {
    let mut value = 0_u64;

    for byte_index in 0..10_u32 {
        let byte = *stream
            .get(*cursor)
            .filter(|_| *cursor < end)
            .ok_or_else(|| {
                BinaryError::invalid_data(format!("{context} contains a truncated ULEB128 value"))
            })?;
        *cursor += 1;
        let payload = u64::from(byte & 0x7f);

        if byte_index == 9 && payload > 1 {
            return Err(BinaryError::invalid_data(format!(
                "{context} contains an overflowing ULEB128 value"
            )));
        }
        value |= payload << (byte_index * 7);

        if byte & 0x80 == 0 {
            if byte_index != 0 && payload == 0 {
                return Err(BinaryError::invalid_data(format!(
                    "{context} contains a non-canonical ULEB128 value"
                )));
            }
            return Ok(value);
        }
    }

    Err(BinaryError::invalid_data(format!(
        "{context} contains an overflowing ULEB128 value"
    )))
}

fn read_sleb(stream: &[u8], cursor: &mut usize, context: &str) -> Result<i64> {
    let mut value = 0_i128;
    let mut shift = 0_u32;

    for _ in 0..10 {
        let byte = *stream.get(*cursor).ok_or_else(|| {
            BinaryError::invalid_data(format!("{context} contains a truncated SLEB128 value"))
        })?;
        *cursor += 1;
        value |= i128::from(byte & 0x7f) << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 {
                value |= (-1_i128) << shift;
            }
            return i64::try_from(value).map_err(|_| {
                BinaryError::invalid_data(format!(
                    "{context} contains an overflowing SLEB128 value"
                ))
            });
        }
    }

    Err(BinaryError::invalid_data(format!(
        "{context} contains an overflowing SLEB128 value"
    )))
}

fn read_c_string<'a>(
    stream: &'a [u8],
    cursor: &mut usize,
    end: usize,
    context: &str,
) -> Result<&'a str> {
    let remainder = stream.get(*cursor..end).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} string offset exceeds its stream"))
    })?;
    let terminator = remainder
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            BinaryError::invalid_data(format!("{context} contains an unterminated string"))
        })?;
    if terminator > MAX_NAME_BYTES {
        return Err(BinaryError::invalid_data(format!(
            "{context} string is {terminator} bytes; limit is {MAX_NAME_BYTES}"
        )));
    }
    let value = std::str::from_utf8(&remainder[..terminator]).map_err(|error| {
        BinaryError::invalid_data(format!("{context} contains invalid UTF-8: {error}"))
    })?;
    *cursor = cursor.checked_add(terminator + 1).ok_or_else(|| {
        BinaryError::invalid_data(format!("{context} string range overflows usize"))
    })?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BinaryFormatParser, formats::macho::MachOParser};
    use goblin::mach::{Mach, load_command};

    fn push_uleb(output: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn uleb_len(mut value: usize) -> usize {
        let mut length = 1;
        while value >= 0x80 {
            value >>= 7;
            length += 1;
        }
        length
    }

    fn append_single_child_node(output: &mut Vec<u8>) {
        let start = output.len();
        let child_offset = (1..=10)
            .map(|encoded_length| start + 4 + encoded_length)
            .find(|offset| uleb_len(*offset) == *offset - start - 4)
            .expect("a usize offset has a bounded ULEB128 encoding");

        output.extend_from_slice(&[0x00, 0x01, b'a', 0x00]);
        push_uleb(output, child_offset as u64);
        assert_eq!(output.len(), child_offset);
    }

    fn append_shared_child_node(output: &mut Vec<u8>) {
        let start = output.len();
        let (child_offset, encoded_length) = (1..=10)
            .map(|encoded_length| (start + 6 + 2 * encoded_length, encoded_length))
            .find(|(offset, encoded_length)| uleb_len(*offset) == *encoded_length)
            .expect("a usize offset has a bounded ULEB128 encoding");

        output.extend_from_slice(&[0x00, 0x02, b'a', 0x00]);
        push_uleb(output, child_offset as u64);
        output.extend_from_slice(&[b'b', 0x00]);
        push_uleb(output, child_offset as u64);
        assert_eq!(uleb_len(child_offset), encoded_length);
        assert_eq!(output.len(), child_offset);
    }

    fn macho_with_dyld_streams(
        bind: &[u8],
        weak_bind: &[u8],
        lazy_bind: &[u8],
        exports: &[u8],
    ) -> Vec<u8> {
        const HEADER_SIZE: usize = 32;
        const SEGMENT_COMMAND_SIZE: usize = 72;
        const DYLD_INFO_COMMAND_SIZE: usize = 48;
        const STREAM_START: usize = 0x200;

        let mut data = vec![0_u8; 0x1000];
        data[..4].copy_from_slice(&goblin::mach::header::MH_MAGIC_64.to_le_bytes());
        data[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        data[8..12].copy_from_slice(&3_u32.to_le_bytes());
        data[12..16].copy_from_slice(&2_u32.to_le_bytes());
        data[16..20].copy_from_slice(&2_u32.to_le_bytes());
        data[20..24].copy_from_slice(
            &((SEGMENT_COMMAND_SIZE + DYLD_INFO_COMMAND_SIZE) as u32).to_le_bytes(),
        );

        let segment = HEADER_SIZE;
        data[segment..segment + 4].copy_from_slice(&load_command::LC_SEGMENT_64.to_le_bytes());
        data[segment + 4..segment + 8]
            .copy_from_slice(&(SEGMENT_COMMAND_SIZE as u32).to_le_bytes());
        data[segment + 8..segment + 14].copy_from_slice(b"__DATA");
        data[segment + 24..segment + 32].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[segment + 32..segment + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[segment + 48..segment + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        data[segment + 56..segment + 60].copy_from_slice(&3_u32.to_le_bytes());
        data[segment + 60..segment + 64].copy_from_slice(&3_u32.to_le_bytes());

        let dyld = HEADER_SIZE + SEGMENT_COMMAND_SIZE;
        data[dyld..dyld + 4].copy_from_slice(&load_command::LC_DYLD_INFO_ONLY.to_le_bytes());
        data[dyld + 4..dyld + 8].copy_from_slice(&(DYLD_INFO_COMMAND_SIZE as u32).to_le_bytes());

        let mut stream_offset = STREAM_START;
        for (field_offset, stream) in [(16, bind), (24, weak_bind), (32, lazy_bind), (40, exports)]
        {
            if stream.is_empty() {
                continue;
            }
            data[dyld + field_offset..dyld + field_offset + 4]
                .copy_from_slice(&(stream_offset as u32).to_le_bytes());
            data[dyld + field_offset + 4..dyld + field_offset + 8]
                .copy_from_slice(&(stream.len() as u32).to_le_bytes());
            data[stream_offset..stream_offset + stream.len()].copy_from_slice(stream);
            stream_offset += stream.len();
        }

        data
    }

    fn parser_error(data: &[u8]) -> String {
        MachOParser::parse(data)
            .err()
            .expect("malformed dyld data must be rejected")
            .to_string()
    }

    #[test]
    fn rejects_tiny_bind_count_amplification_before_goblin() {
        let mut bind = vec![0x10, 0x40];
        bind.extend_from_slice(b"_symbol\0");
        bind.extend_from_slice(&[0x70, 0x00, 0xc0]);
        push_uleb(&mut bind, (MAX_PARSED_RECORDS + 1) as u64);
        bind.push(0);
        let data = macho_with_dyld_streams(&bind, &[], &[], &[]);

        assert!(parser_error(&data).contains("record limit"));
    }

    #[test]
    fn rejects_bind_segment_and_library_indices_before_goblin() {
        let mut invalid_segment = vec![0x10, 0x40];
        invalid_segment.extend_from_slice(b"_symbol\0");
        invalid_segment.extend_from_slice(&[0x7f, 0x00, 0x90]);
        let data = macho_with_dyld_streams(&invalid_segment, &[], &[], &[]);
        assert!(parser_error(&data).contains("segment index 15"));

        let mut invalid_library = vec![0x1f, 0x40];
        invalid_library.extend_from_slice(b"_symbol\0");
        invalid_library.extend_from_slice(&[0x70, 0x00, 0x90]);
        let data = macho_with_dyld_streams(&invalid_library, &[], &[], &[]);
        assert!(parser_error(&data).contains("library ordinal 15"));
    }

    #[test]
    fn rejects_unknown_opcode_and_truncated_uleb() {
        let data = macho_with_dyld_streams(&[0xd0], &[], &[], &[]);
        assert!(parser_error(&data).contains("unknown bind opcode"));

        let data = macho_with_dyld_streams(&[0x20, 0x80], &[], &[], &[]);
        assert!(parser_error(&data).contains("truncated ULEB128"));
    }

    #[test]
    fn rejects_cyclic_export_trie_before_recursive_goblin_walker() {
        let exports = [0x00, 0x01, b'a', 0x00, 0x00];
        let data = macho_with_dyld_streams(&[], &[], &[], &exports);

        assert!(parser_error(&data).contains("cycle at node offset 0"));
    }

    #[test]
    fn rejects_invalid_reexport_library_ordinal() {
        let exports = [0x03, EXPORT_SYMBOL_FLAGS_REEXPORT as u8, 0x0f, 0x00, 0x00];
        let data = macho_with_dyld_streams(&[], &[], &[], &exports);

        assert!(parser_error(&data).contains("reexport library ordinal 15"));
    }

    #[test]
    fn rejects_export_trie_depth_before_goblin_recursion() {
        let mut exports = Vec::new();
        for _ in 0..MAX_EXPORT_TRIE_DEPTH {
            append_single_child_node(&mut exports);
        }
        exports.extend_from_slice(&[0x00, 0x00]);
        let data = macho_with_dyld_streams(&[], &[], &[], &exports);

        assert!(parser_error(&data).contains("maximum depth"));
    }

    #[test]
    fn rejects_shared_node_visit_amplification() {
        let mut exports = Vec::new();
        for _ in 0..18 {
            append_shared_child_node(&mut exports);
        }
        exports.extend_from_slice(&[0x00, 0x00]);
        let data = macho_with_dyld_streams(&[], &[], &[], &exports);

        assert!(parser_error(&data).contains("limit"));
    }

    #[test]
    fn accepts_bounded_bind_and_export_streams() {
        let mut bind = vec![0x10, 0x40];
        bind.extend_from_slice(b"_import\0");
        bind.extend_from_slice(&[0x70, 0x00, 0x90, 0x00]);
        let exports = [0x02, 0x00, 0x10, 0x00];
        let data = macho_with_dyld_streams(&bind, &[], &[], &exports);
        let macho = match Mach::parse(&data).expect("fixture must parse") {
            Mach::Binary(macho) => macho,
            Mach::Fat(_) => panic!("fixture must be thin"),
        };

        validate(&macho, &data).expect("bounded streams must pass preflight");
        MachOParser::parse(&data).expect("bounded streams must parse");
    }
}
