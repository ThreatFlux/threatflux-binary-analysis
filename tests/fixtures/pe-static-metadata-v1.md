# PE static metadata v1 fixture manifest

These fixtures are generated in memory by
`src/formats/pe.rs::enrichment_tests::build_fixture`. They are inert PE images
that contain a single `ret` instruction and declarative import, Rich Header,
and resource structures. They are original project test data covered by the
repository's MIT license; they are never executed or loaded.

The generator emits both PE32 and PE32+ from explicit little-endian fields. It
uses three contiguous 512-byte sections (`.text`, `.idata`, `.rsrc`), two
ordinary import descriptors, two Rich records, and three resource leaves. The
ordinary imports include a duplicate named import, ws2_32 ordinal 24,
oleaut32 ordinal 2, and unmapped oleaut32 ordinal 500. Resource paths cover a
text type/text name, a numeric type/numeric name, and two language IDs.

## Oracle pins and goldens

- Pefile commit: `9df46f3c7d4a917777547c5f59cb198d3f593b93`.
  The checked-in ordinal tables exactly match its `imphash_oleaut32.py` and
  `imphash_ws2_32.py`; `wsock32.dll` aliases the ws2_32 table.
- LIEF algorithm source: commit
  `d05b3499b6934137e917c009a4df0a9dc8cb11c5`, `src/PE/Binary.cpp`.
  Literal digests were independently replayed with LIEF 0.17.1
  (`fe54643f`) using SHA-256.

| Fixture | Bytes | Full-file SHA-256 | Expected Authenticode SHA-256 |
| --- | ---: | --- | --- |
| PE32 unsigned | 2,048 | `033e65d92c2f9fd54ae9a0b90c55122a281479a911b305c1d9a9fb65be91dba3` | `7e0bd00a7d1fec5675722ab51006f0c540dca3f969de66b0592f892058ef6f2e` |
| PE32+ unsigned | 2,048 | `e9da6dad7eacd36b9b6aa1796e5b8e3f5c18b587468309996ea85a8907a2d9d0` | `1f3c262a4dd40a4c1bf14f328ee07913a031cffdcb6f3c1c7bc7b23f8ac41e15` |
| PE32+ test-certificate table | 2,064 | `70c57cac4a90832f31d52735265ac9c10a513095509e2a008ea516c299a92e32` | `1f3c262a4dd40a4c1bf14f328ee07913a031cffdcb6f3c1c7bc7b23f8ac41e15` |
| PE32+ seven-byte overlay | 2,055 | `89f57dd45639c8bf69742d66f5e5a2d3070b132b9c3c3379785ebdd091182547` | `93232b0c786b5111217c721596dba9da653983886e9bc0a3b81b45a0975f1ac2` |

All import-bearing fixtures have pefile-compatible imphash
`7684b36d94140192cfc39dac79e7a5fa`. Regressions also derive gap,
overlap, non-file-backed section, malformed Rich Header, resource cycle,
ambiguous resource RVA, empty directory, missing directory, and exhausted
record-budget controls from these bytes.

`analysis-result-0.3.3.json` is a fixed, hand-inspected representation of the
released v0.3.3 `AnalysisResult` wire schema. It retains section preview bytes
and `file_size` so the compatibility reader is tested against archived JSON,
not a value serialized from the current Rust model.
