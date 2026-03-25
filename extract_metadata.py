#!/usr/bin/env python3
"""
OpenWrt firmware metadata extractor (proof of concept).

Primary path:
    - Parse fwtool trailers from EOF.
    - Extract metadata JSON without decompressing the firmware.

Fallback path:
    - For non-fwtool images (x86/armsr/armvirt combined images or other
      derivatives), this script returns a clear stub result and documents the
      next-stage strategy (kernel decompression + DTB scan).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple


FWIMAGE_MAGIC = 0x46577830  # "FWx0"
FWIMAGE_TRAILER_SIZE = 16
FWIMAGE_HEADER_SIZE = 8

FWIMAGE_SIGNATURE = 0
FWIMAGE_INFO = 1

DEFAULT_MAX_FILE_SIZE = 8 * 1024 * 1024 * 1024  # 8 GiB safety limit
DEFAULT_MAX_METADATA_BYTES = 30 * 1024  # matches fwtool METADATA_MAXLEN
DEFAULT_SCAN_WINDOW = 128 * 1024  # bounded tail scan for fallback heuristics


class ExtractionError(Exception):
    """Base extraction exception."""


class FileTooLargeError(ExtractionError):
    """Raised when file exceeds configured safety limit."""


class InvalidFormatError(ExtractionError):
    """Raised when firmware structure cannot be parsed safely."""


class MetadataNotFoundError(ExtractionError):
    """Raised when fwtool metadata trailer is not present."""


class MetadataValidationError(ExtractionError):
    """Raised when metadata bytes/JSON fail validation."""


class AnalysisStatus(str, Enum):
    SUCCESS = "success"
    NEEDS_FALLBACK = "needs_fallback"
    ERROR = "error"


@dataclass(frozen=True)
class Trailer:
    magic: int
    crc32_be: int
    chunk_type: int
    size_be: int

    @property
    def size(self) -> int:
        return self.size_be

    @property
    def crc32(self) -> int:
        return self.crc32_be


@dataclass
class FirmwareAnalysis:
    status: AnalysisStatus
    source_path: str
    file_size: int
    metadata: Optional[Dict[str, Any]] = None
    metadata_version: Optional[str] = None
    chunk_crc_valid: Optional[bool] = None
    message: Optional[str] = None
    fallback: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "status": self.status.value,
            "source_path": self.source_path,
            "file_size": self.file_size,
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        if self.metadata_version is not None:
            payload["metadata_version"] = self.metadata_version
        if self.chunk_crc_valid is not None:
            payload["chunk_crc_valid"] = self.chunk_crc_valid
        if self.message:
            payload["message"] = self.message
        if self.fallback is not None:
            payload["fallback"] = self.fallback
        return payload


class FirmwareFile:
    """Binary firmware reader with safe seek/read helpers."""

    def __init__(self, path: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> None:
        self.path = path
        self.max_file_size = max_file_size
        self._file: Optional[BinaryIO] = None
        self._size: Optional[int] = None

    def __enter__(self) -> "FirmwareFile":
        self._file = self.path.open("rb")
        self._file.seek(0, io.SEEK_END)
        self._size = self._file.tell()
        if self._size > self.max_file_size:
            raise FileTooLargeError(
                f"file size {self._size} exceeds limit {self.max_file_size}"
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._file:
            self._file.close()
        self._file = None

    @property
    def size(self) -> int:
        if self._size is None:
            raise RuntimeError("file not opened")
        return self._size

    def _ensure_open(self) -> BinaryIO:
        if self._file is None:
            raise RuntimeError("file not opened")
        return self._file

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise InvalidFormatError("negative offset/length requested")
        end = offset + length
        if end > self.size:
            raise InvalidFormatError(
                f"read out of bounds: offset={offset}, length={length}, size={self.size}"
            )
        fh = self._ensure_open()
        fh.seek(offset, io.SEEK_SET)
        data = fh.read(length)
        if len(data) != length:
            raise InvalidFormatError("short read from firmware file")
        return data

    def read_tail(self, length: int) -> bytes:
        length = min(length, self.size)
        return self.read_at(self.size - length, length)


class FwToolMetadataExtractor:
    """
    Extractor for fwtool metadata trailers.

    fwtool appends chunks ending in a trailer:
      struct fwimage_trailer {
          uint32 magic;   // big-endian FWIMAGE_MAGIC
          uint32 crc32;   // big-endian CRC32 over [all bytes before this trailer]
          uint8  type;    // FWIMAGE_SIGNATURE(0) or FWIMAGE_INFO(1)
          uint8  pad[3];
          uint32 size;    // big-endian total chunk size including trailer
      }

    Metadata chunk payload layout:
      fwimage_header (8 bytes: version, flags) + JSON bytes + trailer.
    """

    TRAILER_STRUCT = struct.Struct(">IIB3sI")

    def __init__(self, max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES) -> None:
        self.max_metadata_bytes = max_metadata_bytes

    def extract(self, fw: FirmwareFile, verify_crc: bool = True) -> Tuple[Dict[str, Any], bool]:
        cursor = fw.size
        seen_any_trailer = False
        crc_valid_for_metadata = False

        while cursor >= FWIMAGE_TRAILER_SIZE:
            trailer_offset = cursor - FWIMAGE_TRAILER_SIZE
            trailer_bytes = fw.read_at(trailer_offset, FWIMAGE_TRAILER_SIZE)
            trailer = self._parse_trailer(trailer_bytes)

            if trailer.magic != FWIMAGE_MAGIC:
                if seen_any_trailer:
                    # We already parsed at least one valid trailer chain element;
                    # stop when the chain ends.
                    break
                raise MetadataNotFoundError("fwtool trailer magic not found at EOF chain")

            seen_any_trailer = True
            chunk_start, data_start, data_len = self._compute_chunk_layout(
                cursor=cursor, trailer=trailer
            )

            if trailer.chunk_type == FWIMAGE_INFO:
                metadata = self._read_metadata_chunk(
                    fw=fw, data_start=data_start, data_len=data_len
                )
                if verify_crc:
                    crc_valid_for_metadata = self._verify_crc(
                        fw=fw, trailer=trailer, trailer_offset=trailer_offset
                    )
                else:
                    crc_valid_for_metadata = True
                return metadata, crc_valid_for_metadata

            cursor = chunk_start

        raise MetadataNotFoundError("fwtool metadata chunk (FWIMAGE_INFO) not found")

    @classmethod
    def _parse_trailer(cls, blob: bytes) -> Trailer:
        if len(blob) != FWIMAGE_TRAILER_SIZE:
            raise InvalidFormatError("invalid fwtool trailer length")
        magic, crc32_be, chunk_type, _pad, size_be = cls.TRAILER_STRUCT.unpack(blob)
        return Trailer(magic=magic, crc32_be=crc32_be, chunk_type=chunk_type, size_be=size_be)

    def _compute_chunk_layout(
        self, *, cursor: int, trailer: Trailer
    ) -> Tuple[int, int, int]:
        size = trailer.size
        if size < FWIMAGE_TRAILER_SIZE:
            raise InvalidFormatError(f"invalid trailer size field: {size}")

        chunk_start = cursor - size
        if chunk_start < 0:
            raise InvalidFormatError("chunk start before BOF")

        data_start = chunk_start
        data_len = size - FWIMAGE_TRAILER_SIZE
        return chunk_start, data_start, data_len

    def _read_metadata_chunk(
        self, *, fw: FirmwareFile, data_start: int, data_len: int
    ) -> Dict[str, Any]:
        if data_len < FWIMAGE_HEADER_SIZE:
            raise MetadataValidationError("metadata chunk too small for fwimage header")

        raw = fw.read_at(data_start, data_len)
        version, _flags = struct.unpack(">II", raw[:FWIMAGE_HEADER_SIZE])
        if version != 0:
            raise MetadataValidationError(f"unsupported fwimage header version: {version}")

        metadata_bytes = raw[FWIMAGE_HEADER_SIZE:]
        if len(metadata_bytes) > self.max_metadata_bytes:
            raise MetadataValidationError(
                f"metadata bytes {len(metadata_bytes)} exceed configured limit {self.max_metadata_bytes}"
            )
        if not metadata_bytes:
            raise MetadataValidationError("metadata JSON payload is empty")

        try:
            metadata_text = metadata_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MetadataValidationError(f"metadata is not valid UTF-8: {exc}") from exc

        try:
            decoded = json.loads(metadata_text)
        except json.JSONDecodeError as exc:
            raise MetadataValidationError(f"metadata is not valid JSON: {exc}") from exc

        if not isinstance(decoded, dict):
            raise MetadataValidationError("metadata JSON root must be an object")
        return decoded

    def _verify_crc(self, *, fw: FirmwareFile, trailer: Trailer, trailer_offset: int) -> bool:
        """
        Verify fwtool trailer CRC:
            trailer.crc32 == crc32(all bytes before trailer)
        """
        crc = 0
        remaining = trailer_offset
        chunk = 1024 * 1024
        pos = 0
        while remaining > 0:
            read_len = min(remaining, chunk)
            data = fw.read_at(pos, read_len)
            crc = zlib.crc32(data, crc)
            remaining -= read_len
            pos += read_len

        expected = trailer.crc32
        computed = (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
        return computed == expected


class NonSysupgradeFallbackAnalyzer:
    """
    Stub analyzer for images lacking fwtool metadata.

    Intended production strategy for disk images (x86/armsr/older armvirt) and
    other non-sysupgrade artifacts:
      1) Detect container and kernel segments.
      2) Stream-decompress likely kernel blobs with hard output limits.
      3) Scan decompressed output for DTB magic (0xD00DFEED) and parse DTB header
         totalsize/version to validate candidates.
      4) Derive board/model hints from DTB compatible strings and map to known
         OpenWrt target metadata.
      5) If confidence remains low, require manual override in admin UI.
    """

    def __init__(self, scan_window: int = DEFAULT_SCAN_WINDOW) -> None:
        self.scan_window = scan_window

    def analyze(self, fw: FirmwareFile) -> Dict[str, Any]:
        tail = fw.read_tail(self.scan_window)
        head = fw.read_at(0, min(1024, fw.size))
        looks_like_disk = self._looks_like_disk_image(fw.size, head, tail)

        return {
            "reason": "fwtool metadata not found",
            "detected_image_family": "disk-image" if looks_like_disk else "unknown",
            "recommendation": (
                "Run secondary parser: locate compressed kernel, stream-decompress with limits, "
                "scan for DTB magic 0xD00DFEED, parse DTB totalsize/version, then infer device."
            ),
            "safe_limits": {
                "max_decompressed_bytes": 256 * 1024 * 1024,
                "max_expand_ratio": 200,
            },
            "note": (
                "This script intentionally stops before decompression. In production, perform "
                "fallback in async workers and return manual override required on low confidence."
            ),
        }

    @staticmethod
    def _looks_like_disk_image(file_size: int, head: bytes, tail: bytes) -> bool:
        # Heuristic only: common raw disk images are large and contain MBR/GPT markers.
        has_mbr = len(head) >= 512 and head[510:512] == b"\x55\xaa"
        has_gpt = len(head) >= 520 and head[512:520] == b"EFI PART"
        has_tail_mbr = len(tail) >= 2 and tail[-2:] == b"\x55\xaa"
        return file_size >= 64 * 1024 * 1024 or has_mbr or has_gpt or has_tail_mbr


class FirmwareAnalyzer:
    def __init__(
        self,
        *,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES,
    ) -> None:
        self.max_file_size = max_file_size
        self.fwtool_extractor = FwToolMetadataExtractor(
            max_metadata_bytes=max_metadata_bytes
        )
        self.fallback_analyzer = NonSysupgradeFallbackAnalyzer()

    def analyze(self, path: Path, verify_crc: bool = True) -> FirmwareAnalysis:
        with FirmwareFile(path=path, max_file_size=self.max_file_size) as fw:
            try:
                metadata, crc_ok = self.fwtool_extractor.extract(
                    fw=fw, verify_crc=verify_crc
                )
                return FirmwareAnalysis(
                    status=AnalysisStatus.SUCCESS,
                    source_path=str(path),
                    file_size=fw.size,
                    metadata=metadata,
                    metadata_version=_safe_get(metadata, "metadata_version"),
                    chunk_crc_valid=crc_ok,
                    message="fwtool metadata extracted successfully",
                )
            except MetadataNotFoundError:
                fallback = self.fallback_analyzer.analyze(fw)
                return FirmwareAnalysis(
                    status=AnalysisStatus.NEEDS_FALLBACK,
                    source_path=str(path),
                    file_size=fw.size,
                    message="No fwtool metadata found; fallback analysis required",
                    fallback=fallback,
                )


def _safe_get(payload: Dict[str, Any], key: str) -> Optional[str]:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract OpenWrt firmware metadata (fwtool-aware)."
    )
    parser.add_argument("firmware", type=Path, help="Path to firmware image")
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        help=f"Maximum allowed file size in bytes (default: {DEFAULT_MAX_FILE_SIZE})",
    )
    parser.add_argument(
        "--max-metadata-bytes",
        type=int,
        default=DEFAULT_MAX_METADATA_BYTES,
        help=f"Maximum metadata payload bytes (default: {DEFAULT_MAX_METADATA_BYTES})",
    )
    parser.add_argument(
        "--no-crc-verify",
        action="store_true",
        help="Skip fwtool trailer CRC verification",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    path = args.firmware

    if not path.exists():
        print(json.dumps({"status": "error", "message": f"file not found: {path}"}))
        return 2
    if not path.is_file():
        print(json.dumps({"status": "error", "message": f"not a file: {path}"}))
        return 2

    analyzer = FirmwareAnalyzer(
        max_file_size=args.max_file_size,
        max_metadata_bytes=args.max_metadata_bytes,
    )

    try:
        result = analyzer.analyze(path, verify_crc=(not args.no_crc_verify))
    except ExtractionError as exc:
        payload = {
            "status": "error",
            "source_path": str(path),
            "message": str(exc),
        }
        print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
        return 1
    except OSError as exc:
        payload = {
            "status": "error",
            "source_path": str(path),
            "message": f"I/O error: {exc}",
        }
        print(json.dumps(payload, indent=2 if args.pretty else None, sort_keys=True))
        return 1

    print(json.dumps(result.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
    return 0 if result.status == AnalysisStatus.SUCCESS else 3


if __name__ == "__main__":
    sys.exit(main())
