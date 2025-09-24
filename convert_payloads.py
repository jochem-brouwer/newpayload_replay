#!/usr/bin/env python3
import json
from pathlib import Path
from collections import defaultdict

PAYLOADS_DIR = Path("payloads")
OUTPUT_DIR = Path("test_output")
OUTPUT_DIR.mkdir(exist_ok=True)

entries = []  # list of (int_block_number, hex_block_number, gas_limit, file_path, json_obj)
block_map = defaultdict(list)  # hex_block_number -> [file paths]

for json_file in PAYLOADS_DIR.rglob("*.json"):
    try:
        with open(json_file, "r") as f:
            data = json.load(f)

        if (
            isinstance(data, dict)
            and data.get("method", "").startswith("engine_newPayload")
            and isinstance(data.get("params"), list)
            and len(data["params"]) > 0
            and isinstance(data["params"][0], dict)
        ):
            params0 = data["params"][0]
            hex_bn = params0.get("blockNumber")
            gas_limit = params0.get("gasLimit")
            if hex_bn:
                int_bn = int(hex_bn, 16)
                entries.append((int_bn, hex_bn, gas_limit, json_file, data))
                block_map[hex_bn].append(str(json_file))
    except Exception as e:
        print(f"⚠️ Could not read {json_file}: {e}")

# Sort numerically by blockNumber
entries.sort(key=lambda x: x[0])

# --- Console output ---
print("\n=== Block Numbers & Gas Limits (sorted) ===")
for int_bn, hex_bn, gas_limit, _, _ in entries:
    print(f"BlockNumber {hex_bn} ({int_bn}) | gasLimit {gas_limit}")

print("\n=== Duplicates ===")
dupes = {bn: files for bn, files in block_map.items() if len(files) > 1}
if dupes:
    for bn, files in dupes.items():
        print(f"BlockNumber {bn} appears in:")
        for f in files:
            print(f"   {f}")
else:
    print("No duplicate blockNumbers found.")

# --- Write engine_requests.txt ---
output_file = OUTPUT_DIR / "engine_requests.txt"
with open(output_file, "w") as out:
    for _, _, _, _, data in entries:
        # Flatten JSON to a single line (no spaces)
        out.write(json.dumps(data, separators=(",", ":")) + "\n")

print(f"\n✅ Written flattened payloads to {output_file}")
