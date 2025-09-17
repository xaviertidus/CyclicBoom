# CyclicBoom

[![Python 2.7.1](https://img.shields.io/badge/Python-2.7.1-yellow.svg)](https://www.python.org/downloads/release/python-2710/)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/CyclicBoom.svg)](https://github.com/yourusername/CyclicBoom)

CyclicBoom: A Python 2.7.1 tool for buffer overflow testing and payload creation. Generate cyclic patterns, search for EIP offsets, or pack payloads with shellcode. Customize with prefix/suffix (string or hex), avoid chars, and add NOP sleds. Ideal for exploit dev with Immunity Debugger. MIT licensed.

## Features

- **Cyclic Pattern Generation**: Creates unique, non-repeating 4-byte patterns using printable ASCII (A-Z, a-z, 0-9) to identify buffer overflow offsets.
- **EIP Offset Search**: Finds the exact offset where EIP is overwritten, with automatic little/big-endian detection.
- **Payload Packing**: Combines cyclic patterns, prefixes/suffixes, NOP sleds, and shellcode (raw or hex) for exploit payloads.
- **Flexible Length Control**: Use `--length` for exact cyclic pattern size or `--max-length` for total output capping (mutually exclusive, `pack` mode uses `--length`).
- **Prefix/Suffix Customization**: Support for string literals (`--prefix`/`--suffix`) or hex byte strings (`--prefix-byte`/`--suffix-byte`) for precise control, e.g., overwriting EIP.
- **Character Avoidance**: Optionally skip specified bytes (e.g., `\x00`) in cyclic patterns.
- **Debugger Integration**: Outputs reports and prompts for Mona in Immunity Debugger (`!mona suggest`).
- **Python 2.7.1 Compatible**: Lightweight, no external dependencies.

## Installation

1. **Prerequisites**: Python 2.7.1 (tested; legacy exploit environments).
2. **Clone the Repo**:
   ```
   git clone https://github.com/yourusername/CyclicBoom.git
   cd CyclicBoom
   ```
3. **Run Directly**: No installation needed—execute with `python cyclicboom.py`.
   - Ensure Python 2.7.1 is in your PATH.

## Usage

Run with `python cyclicboom.py [arguments]`. Use `--help` for details:

```
python cyclicboom.py --help
```

### Command-Line Arguments

| Argument | Type | Description | Example |
|----------|------|-------------|---------|
| `--mode` | `str` (choices: `generate`, `search`, `pack`) | Operation mode: `generate` creates a cyclic pattern, `search` finds EIP offset, `pack` builds a payload with shellcode. Default: `generate`. | `--mode pack` |
| `--output` | `str` | File path to write output (required for `generate` and `pack`). | `--output payload.bin` |
| `--length` | `int` | Exact length of cyclic pattern (excludes prefix/suffix). Required for `generate` (or `--max-length`) and `pack`. | `--length 1011` (1011-byte cyclic pattern) |
| `--max-length` | `int` | Maximum total length of output (prefix + cyclic + suffix). Mutually exclusive with `--length`, used in `generate` only. | `--max-length 1024` (caps total at 1024 bytes) |
| `--prefix` | `str` | String to prepend to cyclic pattern. Mutually exclusive with `--prefix-byte`. Default: empty. | `--prefix "HEAD"` (prepends "HEAD") |
| `--prefix-byte` | `str` (hex) | Hex byte string to prepend (e.g., `0x00112233` → `\x00\x11\x22\x33`). Mutually exclusive with `--prefix`. Default: empty. Variable length (even hex chars). | `--prefix-byte 0xDEADBEEF` (prepends 4 bytes) |
| `--suffix` | `str` | String to append to cyclic pattern. Mutually exclusive with `--suffix-byte`. Default: empty. | `--suffix "TAIL"` (appends "TAIL") |
| `--suffix-byte` | `str` (hex) | Hex byte string to append (e.g., `0xF9350101` → `\xF9\x35\x01\x01`). Mutually exclusive with `--suffix`. Default: empty. Variable length (even hex chars). | `--suffix-byte 0xF9350101` (appends 4 bytes for EIP) |
| `--avoid-chars` | `str` (byte literal) | Byte string of chars to avoid in cyclic pattern (e.g., `'\x00\x0a'`). Default: empty (none avoided). | `--avoid-chars "\x00\x0a"` (avoids null and LF) |
| `--input` | `str` | Path to input file with cyclic pattern. Required for `search`. | `--input pattern.bin` |
| `--eip-value` | `str` (4-byte hex) | 4-byte hex string overwriting EIP (e.g., `41424344`). Required for `search`. Handles little/big-endian. | `--eip-value 0x41424344` |
| `--shellcode-payload` | `str` | File path to shellcode file. Required for `pack`. | `--shellcode-payload shellcode.bin` |
| `--payload-format` | `str` (choices: `hex`, `raw`) | Format of shellcode file: `hex` for hex string, `raw` for binary (default: `raw`). Used in `pack`. | `--payload-format hex` |
| `--nop-sled-length` | `int` | Number of NOP bytes (`\x90`) to insert before shellcode in `pack`. Default: 0. | `--nop-sled-length 16` (adds 16 NOPs) |

**Notes**:
- Hex strings (`--eip-value`, `--prefix-byte`, `--suffix-byte`) support optional `0x` prefix, case-insensitive.
- In `generate`, either `--length` or `--max-length` is required.
- In `pack`, `--length`, `--output`, and `--shellcode-payload` are required.
- Output files are written in binary mode for raw bytes.
- Pattern generation may truncate if `--avoid-chars` limits unique combos (~1.7M max).

### Generate Mode Examples

1. **Basic Pattern**:
   ```
   python cyclicboom.py --mode generate --output pattern.bin --length 500
   ```
   - Output: 500-byte cyclic pattern.
   - Report: `Prefix: 0 bytes, Cyclic pattern: 500 bytes, Suffix: 0 bytes, Total: 500 bytes`

2. **With Prefix/Suffix Strings**:
   ```
   python cyclicboom.py --mode generate --output prefixed.bin --max-length 200 --prefix "START" --suffix "END"
   ```
   - Cyclic: 200 - 5 ("START") - 3 ("END") = 192 bytes.
   - Total: 200 bytes.

3. **With Hex Suffix for EIP**:
   ```
   python cyclicboom.py --mode generate --output eip.bin --length 1011 --suffix-byte 0xF9350101
   ```
   - 1011-byte cyclic + 4-byte suffix (`\xF9\x35\x01\x01`) for EIP at offset 1012.

4. **Avoiding Chars**:
   ```
   python cyclicboom.py --mode generate --output safe.bin --length 300 --avoid-chars "\x00\x0a\x0d"
   ```
   - Skips null, LF, CR in pattern.

### Pack Mode Examples

1. **Basic Payload with Shellcode**:
   ```
   python cyclicboom.py --mode pack --output payload.bin --length 1011 --shellcode-payload shellcode.bin --payload-format raw
   ```
   - Payload: 1011-byte cyclic + shellcode.
   - Report includes cyclic and shellcode lengths.

2. **With NOP Sled and Hex Suffix**:
   ```
   python cyclicboom.py --mode pack --output exploit.bin --length 1011 --suffix-byte 0xF9350101 --nop-sled-length 16 --shellcode-payload shellcode.bin --payload-format raw
   ```
   - Payload: 1011-byte cyclic + 4-byte EIP (`\xF9\x35\x01\x01`) + 16 NOPs + shellcode.

3. **With Hex Shellcode**:
   ```
   python cyclicboom.py --mode pack --output exploit.bin --length 500 --prefix-byte 0xDEADBEEF --shellcode-payload shellcode.hex --payload-format hex
   ```
   - Reads `shellcode.hex` as hex string, converts to bytes.

### Search Mode Examples

1. **Basic EIP Search**:
   ```
   python cyclicboom.py --mode search --input pattern.bin --eip-value 41424344
   ```
   - If found: `EIP value found at offset 512 (little-endian), Last byte before EIP: offset 511, EIP byte: offset 512`

2. **Big-Endian Detection**:
   - If `0x41424344` is reversed, reports `(big-endian)`.

### Use Cases

1. **Finding Buffer Overflow Offset**:
   - Generate: `python cyclicboom.py --mode generate --output crash.bin --length 2000`
   - Feed `crash.bin` to the app (e.g., via socket).
   - Crash in Immunity Debugger, note EIP (e.g., `0x61416141`).
   - Search: `python cyclicboom.py --mode search --input crash.bin --eip-value 61416141`
   - Result: Offset (e.g., 1024).

2. **Crafting Return-to-LibC Payload**:
   - After finding offset 1011: `python cyclicboom.py --mode pack --output rtlg.bin --length 1011 --suffix-byte 0xF9350101 --nop-sled-length 16 --shellcode-payload shellcode.bin --payload-format raw`
   - Replace `0xF9350101` with `system()` address.
   - Test with Mona: `!mona suggest`.

3. **SEH Overwrite with Avoided Chars**:
   - Generate: `python cyclicboom.py --mode generate --output seh.bin --length 500 --avoid-chars "\x00" --suffix "EB06POPPOP"`
   - Search for SEH offset, then pack with shellcode.

4. **Shellcode Delivery with NOP Sled**:
   - Generate shellcode with `msfvenom -p windows/exec CMD=calc.exe -f raw > calc.bin`.
   - Pack: `python cyclicboom.py --mode pack --output exploit.bin --length 1011 --suffix-byte 0xF9350101 --nop-sled-length 32 --shellcode-payload calc.bin --payload-format raw`
   - Delivers shellcode after precise EIP control.

## Troubleshooting

- **Invalid Hex**: Ensure even-length hex strings (`--prefix-byte`, `--suffix-byte`, `--payload-format hex`).
- **No EIP Match**: Verify input file matches generated pattern; check endianness.
- **Pattern Truncation**: Reduce `--length` or relax `--avoid-chars` if unique combos are exhausted.
- **Shellcode Errors**: Ensure `--shellcode-payload` exists and matches `--payload-format`.
- **Python Version**: Use 2.7.1 for compatibility.

## Contributing

Pull requests welcome! Fork, branch, and submit PRs. Maintain Python 2.7.1 compatibility.

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit changes (`git commit -m 'Add some AmazingFeature'`).
4. Push (`git push origin feature/AmazingFeature`).
5. Open a PR.

## License

Distributed under the MIT License. See `LICENSE` for more info.

---

*Built with ❤️ for exploit devs. Questions? Open an issue!*