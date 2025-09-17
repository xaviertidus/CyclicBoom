# CyclicBoom

[![Python 2.7.1](https://img.shields.io/badge/Python-2.7.1-yellow.svg)](https://www.python.org/downloads/release/python-2710/)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/CyclicBoom.svg)](https://github.com/yourusername/CyclicBoom)

CyclicBoom: A Python 2.7.1 tool for buffer overflow testing. Generate cyclic patterns with customizable length, prefix/suffix (string or hex), and avoided chars. Search for EIP offsets with endianness detection. Ideal for exploit dev with Immunity Debugger. MIT licensed.

## Features

- **Cyclic Pattern Generation**: Creates unique, non-repeating 4-byte patterns using printable ASCII characters (A-Z, a-z, 0-9) to reliably identify offsets in buffer overflows.
- **Flexible Length Control**: Use `--length` for exact cyclic pattern size or `--max-length` for total output capping (mutually exclusive).
- **Prefix/Suffix Customization**: Support for string literals (`--prefix`/`--suffix`) or hex byte strings (`--prefix-byte`/`--suffix-byte`) for precise payload crafting, e.g., overwriting EIP with a specific address.
- **Character Avoidance**: Optionally skip specified bytes (e.g., nulls `\x00`) in the pattern to avoid issues with string handling.
- **EIP Offset Search**: Analyzes generated patterns to find the exact offset where EIP is overwritten, with automatic little-endian/big-endian detection.
- **Debugger Integration**: Outputs reports and prompts for tools like Mona in Immunity Debugger to refine exploits.
- **Python 2.7.1 Compatible**: Lightweight, no external dependencies beyond standard library.

## Installation

1. **Prerequisites**: Python 2.7.1 (tested and compatible; no newer versions due to legacy exploit environments).
2. **Clone the Repo**:
   ```
   git clone https://github.com/yourusername/CyclicBoom.git
   cd CyclicBoom
   ```
3. **Run Directly**: No installation needed—execute with `python cyclicboom.py`.
   - Ensure Python 2.7.1 is in your PATH.

## Usage

Run the script with `python cyclicboom.py [arguments]`. Use `--help` for a full list:

```
python cyclicboom.py --help
```

### Command-Line Arguments

| Argument | Type | Description | Example |
|----------|------|-------------|---------|
| `--mode` | `str` (choices: `generate`, `search`) | Operation mode: `generate` creates a cyclic pattern file; `search` finds the EIP offset in an existing pattern. Default: `generate`. | `--mode search` |
| `--output` | `str` | File path to write the generated pattern (binary mode). Required for `generate` mode. | `--output pattern.bin` |
| `--length` | `int` | Exact length of the cyclic pattern (excludes prefix/suffix). Mutually exclusive with `--max-length`. Use when you know the offset to EIP (e.g., pad up to it). | `--length 1011` (generates 1011-byte cyclic pattern) |
| `--max-length` | `int` | Maximum total length of output (prefix + cyclic + suffix). Mutually exclusive with `--length`. Fills cyclic pattern to fit the total. | `--max-length 1024` (caps total output at 1024 bytes) |
| `--prefix` | `str` | String to prepend to the cyclic pattern. Mutually exclusive with `--prefix-byte`. Default: empty. | `--prefix "HEAD"` (prepends "HEAD") |
| `--prefix-byte` | `str` (hex) | Hex byte string to prepend (e.g., `0x00112233` → `\x00\x11\x22\x33`). Mutually exclusive with `--prefix`. Default: empty. Variable length (even hex chars). | `--prefix-byte 0xDEADBEEF` (prepends 4 bytes) |
| `--suffix` | `str` | String to append to the cyclic pattern. Mutually exclusive with `--suffix-byte`. Default: empty. | `--suffix "TAIL"` (appends "TAIL") |
| `--suffix-byte` | `str` (hex) | Hex byte string to append (e.g., `0xF9350101` → `\xF9\x35\x01\x01`). Mutually exclusive with `--suffix`. Default: empty. Variable length (even hex chars). Ideal for EIP overwrites. | `--suffix-byte 0xF9350101` (appends 4 bytes for EIP control) |
| `--avoid-chars` | `str` (byte literal) | Byte string of characters to avoid in the cyclic pattern (e.g., `'\x00\x0a'` for nulls and newlines). Default: empty (none avoided). Use `ast.literal_eval` for parsing. | `--avoid-chars "\x00\x0a"` (avoids null and LF) |
| `--input` | `str` | Path to the input file containing the cyclic pattern. Required for `search` mode. | `--input pattern.bin` |
| `--eip-value` | `str` (4-byte hex) | 4-byte hex string of the value overwriting EIP (e.g., `41424344` or `0x41424344`). Required for `search` mode. Handles little/big-endian automatically. | `--eip-value 0x41424344` |

**Notes**:
- Hex strings (e.g., `--eip-value`, `--prefix-byte`) support `0x` prefix (optional) and are case-insensitive.
- In `generate` mode, exactly one of `--length` or `--max-length` is required.
- Output files are written in binary mode for raw byte handling.
- If pattern generation hits unique combo limits (rare, ~1.7M patterns), it warns and uses max possible.

### Generate Mode Examples

1. **Basic Generation** (exact cyclic length, no prefix/suffix):
   ```
   python cyclicboom.py --mode generate --output basic_pattern.bin --length 500
   ```
   - Output: 500-byte cyclic pattern written to `basic_pattern.bin`.
   - Report: `Prefix: 0 bytes, Cyclic pattern: 500 bytes, Suffix: 0 bytes, Total: 500 bytes`

2. **With Prefix and Suffix Strings** (max total length):
   ```
   python cyclicboom.py --mode generate --output prefixed_pattern.bin --max-length 200 --prefix "START" --suffix "END"
   ```
   - Cyclic fills remaining: 200 - 5 ("START") - 3 ("END") = 192 bytes.
   - Total output: Exactly 200 bytes.

3. **With Hex Suffix for EIP Overwrite** (exact cyclic to offset):
   ```
   python cyclicboom.py --mode generate --output eip_payload.bin --length 1011 --suffix-byte 0xF9350101
   ```
   - 1011-byte cyclic + 4-byte hex suffix (`\xF9\x35\x01\x01`) to load into EIP at offset 1012.

4. **Avoiding Specific Chars**:
   ```
   python cyclicboom.py --mode generate --output safe_pattern.bin --length 300 --avoid-chars "\x00\x0a\x0d"
   ```
   - Skips patterns containing null, LF, or CR.

### Search Mode Examples

1. **Basic EIP Search** (little-endian assumed):
   ```
   python cyclicboom.py --mode search --input pattern.bin --eip-value 41424344
   ```
   - If found: `EIP value found at offset 512 (little-endian), Last byte before EIP: offset 511, EIP byte: offset 512`
   - Tries little-endian first, then big-endian if needed.

2. **With Big-Endian Detection**:
   - If the value is `0x41424344` but appears reversed in the stack, it reports `(big-endian)`.

## Use Cases

### Use Case 1: Finding Buffer Overflow Offset
1. Generate a long pattern: `python cyclicboom.py --mode generate --output crash.bin --length 2000`
2. Feed `crash.bin` into the vulnerable app (e.g., via netcat or Python socket).
3. Crash in Immunity Debugger; note the EIP value (e.g., `0x61416141`).
4. Search: `python cyclicboom.py --mode search --input crash.bin --eip-value 61416141`
5. Result: Offset (e.g., 1024). Use this to craft a precise payload.

### Use Case 2: Crafting a Return-to-LibC Payload
1. After finding offset (e.g., 1011 bytes to EIP), generate with suffix for system() address:
   ```
   python cyclicboom.py --mode generate --output rtlg_payload.bin --length 1011 --suffix-byte 0xF9350101
   ```
   - Replace `0xF9350101` with actual `system()` address from `objdump`.
2. Append shellcode/nops as needed. Test in debugger with Mona: `!mona suggest`.

### Use Case 3: SEH Overwrite with Avoided Chars
1. For apps sensitive to nulls: `python cyclicboom.py --mode generate --output seh_pattern.bin --max-length 500 --avoid-chars "\x00" --suffix "EB06POPPOP"`
2. Search for SEH/Next SEH offsets post-crash.
3. Refine with hex suffixes for POP-POP-RET gadgets.

## Troubleshooting

- **Invalid Hex**: Ensure even-length hex strings without odd chars (e.g., `0xABC` → error).
- **No EIP Match**: Verify the input file matches the generated pattern; check endianness manually.
- **Pattern Truncation**: If `--avoid-chars` limits combos, reduce length or relax avoids.
- **Python Version**: Strictly 2.7.1; syntax errors? Check `str` vs. `bytes` handling.

## Contributing

Pull requests welcome! Fork, branch, and submit PRs for features/bugs. Focus on maintaining 2.7.1 compatibility.

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit changes (`git commit -m 'Add some AmazingFeature'`).
4. Push (`git push origin feature/AmazingFeature`).
5. Open a PR.

## License

Distributed under the MIT License. See `LICENSE` for more info.

---

*Built with ❤️ for exploit devs. Questions? Open an issue!*