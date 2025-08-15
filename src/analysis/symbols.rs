use crate::types::Symbol;
#[cfg(feature = "symbol-resolution")]
use addr2line::demangle_auto;
#[cfg(feature = "symbol-resolution")]
use gimli::DW_LANG_C_plus_plus;
#[cfg(feature = "symbol-resolution")]
use std::borrow::Cow;

/// Demangle symbol names using DWARF demangling facilities.
///
/// This function populates the `demangled_name` field for each provided
/// [`Symbol`], leaving existing values intact.
#[cfg(feature = "symbol-resolution")]
pub fn demangle_symbols(symbols: &mut [Symbol]) {
    for symbol in symbols.iter_mut() {
        if symbol.demangled_name.is_none() {
            let demangled = demangle_auto(Cow::Borrowed(&symbol.name), Some(DW_LANG_C_plus_plus));
            let demangled = demangled.to_string();
            if demangled != symbol.name {
                symbol.demangled_name = Some(demangled);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SymbolBinding, SymbolType, SymbolVisibility};

    #[cfg(feature = "symbol-resolution")]
    #[test]
    fn test_demangle_symbols() {
        let mut symbols = vec![
            Symbol {
                name: "_ZN3foo3barEv".into(),
                demangled_name: None,
                address: 0,
                size: 0,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: None,
            },
            Symbol {
                name: "plain_symbol".into(),
                demangled_name: None,
                address: 0,
                size: 0,
                symbol_type: SymbolType::Object,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: None,
            },
        ];

        demangle_symbols(&mut symbols);

        assert_eq!(symbols[0].demangled_name.as_deref(), Some("foo::bar()"));
        assert!(symbols[1].demangled_name.is_none());
    }
}
