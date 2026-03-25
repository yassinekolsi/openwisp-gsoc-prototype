# OpenWISP GSoC Prototype: OpenWrt Metadata Extraction

Production-oriented proof of concept for automatic extraction of OpenWrt firmware image metadata.

Primary path:
- Parse `fwtool` trailers from EOF.
- Extract metadata JSON without decompressing the firmware.

Fallback path:
- For non-fwtool images (x86/armsr/armvirt combined images or other derivatives), return a clear fallback result and document next-stage strategy (kernel decompression + DTB scan).

## Script

- `extract_metadata.py`

## Requirements

- Python 3.8+

## Usage

```bash
python3 extract_metadata.py --pretty /path/to/openwrt-sysupgrade.bin
```

Optional flags:

```bash
python3 extract_metadata.py --help
```

## Example output

```json
{
  "chunk_crc_valid": true,
  "file_size": 147,
  "message": "fwtool metadata extracted successfully",
  "metadata": {
    "metadata_version": "1.1",
    "supported_devices": [
      "x86"
    ],
    "version": {
      "dist": "OpenWrt",
      "version": "24.10"
    }
  },
  "metadata_version": "1.1",
  "source_path": "/tmp/example.bin",
  "status": "success"
}
```

## Notes

- The parser is trailer-based and does bounded reads from EOF.
- CRC verification is supported and enabled by default.
- Metadata size and file size limits are enforced for safe operation.
- Non-sysupgrade images are surfaced as `needs_fallback` (not silently accepted).
