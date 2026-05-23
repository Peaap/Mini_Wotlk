from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import time
from dataclasses import dataclass
from pathlib import Path


LUA_SCAN_DLL_START_VA = 0x004DCCF0
SCAN_DLL_START_VA = 0x004E5CB0
SCAN_RETURN_HOOK_VA = 0x004E5E97
START_ADDRESS_VA = 0x0040B7D0
CODE_CAVE_VA = 0x009DE3C0
LOAD_DLL_FN = 0x0086C4E0
AWESOME_DLL = b"AwesomeWotlkLib.dll\x00"

# Build 12340 bytes at the successful tail of ScanDllStart:
#   mov dword ptr [0x00B6AFA0], esi
ORIGINAL_SCAN_RETURN_HOOK = bytes.fromhex("89 35 A0 AF B6 00")

# Bytes from unmodified build 12340 Wow.exe at StartAddress. These are only used
# when cleaning up an older AwesomeWotlkPatch.exe-style patch with --original.
ORIGINAL_START_ADDRESS = bytes.fromhex(
    "55 8B EC E8 98 B5 FF FF 8B 15 E8 11 B3 00 8B 4D"
    " 08 52 89 01 FF 15 D4 F2 9D 00 5D C2 04 00 CC CC"
)


class PatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class PeInfo:
    image_base: int
    number_of_sections: int
    section_table: int
    characteristics_offset: int


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_pe_headers(image: bytes) -> PeInfo:
    if image[:2] != b"MZ":
        raise PatchError("file is not a valid PE image: missing MZ header")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise PatchError("file is not a valid PE image: missing PE header")
    number_of_sections = struct.unpack_from("<H", image, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
    image_base = struct.unpack_from("<I", image, pe_offset + 24 + 28)[0]
    section_table = pe_offset + 24 + optional_header_size
    characteristics_offset = pe_offset + 22
    return PeInfo(image_base, number_of_sections, section_table, characteristics_offset)


def va_to_raw(image: bytes, va: int) -> int:
    pe = read_pe_headers(image)
    for i in range(pe.number_of_sections):
        offset = pe.section_table + i * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", image, offset + 8)
        begin = pe.image_base + virtual_address
        end = begin + max(virtual_size, raw_size)
        if begin <= va < end:
            return raw_pointer + (va - begin)
    raise PatchError(f"VA 0x{va:08X} is not inside a PE section")


def set_large_address_aware(image: bytearray) -> bool:
    pe = read_pe_headers(image)
    characteristics = struct.unpack_from("<H", image, pe.characteristics_offset)[0]
    new_characteristics = characteristics | 0x20
    struct.pack_into("<H", image, pe.characteristics_offset, new_characteristics)
    return characteristics != new_characteristics


def rel32(next_instruction_va: int, target_va: int) -> bytes:
    return struct.pack("<i", target_va - next_instruction_va)


def jmp_rel(current_va: int, target_va: int) -> bytes:
    return b"\xE9" + rel32(current_va + 5, target_va)


def call_rel(current_va: int, target_va: int) -> bytes:
    return b"\xE8" + rel32(current_va + 5, target_va)


def expected_hook() -> bytes:
    return jmp_rel(SCAN_RETURN_HOOK_VA, CODE_CAVE_VA) + b"\x90"


def build_code_cave() -> bytes:
    # This runs at the successful tail of ScanDllStart, replacing:
    #   mov dword ptr [0x00B6AFA0], esi
    #   pop esi
    #   pop ebp
    #   ret
    dll_path_va = CODE_CAVE_VA + 26
    code = bytearray()
    code += b"\x89\x35\xA0\xAF\xB6\x00"  # displaced: mov [0x00B6AFA0], esi
    code += b"\x9C"  # pushfd
    code += b"\x60"  # pushad
    code += b"\x68" + struct.pack("<I", dll_path_va)
    code += call_rel(CODE_CAVE_VA + len(code), LOAD_DLL_FN)
    code += b"\x83\xC4\x04"  # add esp, 4
    code += b"\x61"  # popad
    code += b"\x9D"  # popfd
    code += b"\x5E"  # pop esi
    code += b"\x5D"  # pop ebp
    code += b"\xC3"  # ret
    if len(code) != 26:
        raise PatchError(f"unexpected code cave length: {len(code)}")
    return bytes(code) + AWESOME_DLL


def read_at_va(image: bytes, va: int, size: int) -> bytes:
    raw = va_to_raw(image, va)
    return image[raw : raw + size]


def write_at_va(image: bytearray, va: int, data: bytes) -> None:
    raw = va_to_raw(image, va)
    image[raw : raw + len(data)] = data


def patch_status(image: bytes) -> str:
    hook = read_at_va(image, SCAN_RETURN_HOOK_VA, len(expected_hook()))
    cave = read_at_va(image, CODE_CAVE_VA, len(build_code_cave()))
    if hook == expected_hook() and cave == build_code_cave():
        return "patched"
    if hook.startswith(ORIGINAL_SCAN_RETURN_HOOK):
        return "clean"
    return "unknown"


def restore_original_range(image: bytearray, original: bytes, va: int, size: int) -> dict[str, str | int]:
    data = read_at_va(original, va, size)
    write_at_va(image, va, data)
    return {"va": f"0x{va:08X}", "size": size}


def apply_patch(image: bytearray, original: bytes | None, reset_old_patch: bool) -> dict[str, object]:
    status = patch_status(image)
    if status == "unknown" and not reset_old_patch:
        raise PatchError(
            "Wow.exe hook bytes are neither clean nor already patched. "
            "Use --reset-old-patch --original <clean Wow.exe> if migrating from another patcher."
        )

    actions: dict[str, object] = {"input_status": status, "restored_ranges": []}
    actions["large_address_aware_changed"] = set_large_address_aware(image)

    if reset_old_patch:
        if original is None:
            raise PatchError("--reset-old-patch requires --original <clean Wow.exe>")
        actions["restored_ranges"] = [
            restore_original_range(image, original, LUA_SCAN_DLL_START_VA, 96),
            restore_original_range(image, original, SCAN_DLL_START_VA, 512),
            restore_original_range(image, original, START_ADDRESS_VA, len(ORIGINAL_START_ADDRESS)),
        ]

    write_at_va(image, SCAN_RETURN_HOOK_VA, expected_hook())
    cave = build_code_cave()
    write_at_va(image, CODE_CAVE_VA, cave)
    actions["hook"] = {"va": f"0x{SCAN_RETURN_HOOK_VA:08X}", "size": len(expected_hook())}
    actions["code_cave"] = {"va": f"0x{CODE_CAVE_VA:08X}", "size": len(cave), "dll": AWESOME_DLL.rstrip(b"\x00").decode()}
    return actions


def unpatch(image: bytearray, original: bytes | None) -> dict[str, object]:
    if patch_status(image) != "patched":
        raise PatchError("Wow.exe does not contain this patch")

    actions: dict[str, object] = {"input_status": "patched"}
    write_at_va(image, SCAN_RETURN_HOOK_VA, ORIGINAL_SCAN_RETURN_HOOK)
    actions["hook_restored"] = {"va": f"0x{SCAN_RETURN_HOOK_VA:08X}", "size": len(ORIGINAL_SCAN_RETURN_HOOK)}

    if original is not None:
        cave = read_at_va(original, CODE_CAVE_VA, len(build_code_cave()))
        write_at_va(image, CODE_CAVE_VA, cave)
        actions["code_cave_restored_from_original"] = True
    else:
        actions["code_cave_restored_from_original"] = False
        actions["note"] = "hook removed; code cave bytes left in unused padding"
    return actions


def write_image(path: Path, image: bytearray, backup_prefix: str) -> Path:
    backup = path.with_name(f"{path.name}.{backup_prefix}-{time.strftime('%Y%m%d-%H%M%S')}.bak")
    shutil.copy2(path, backup)
    path.write_bytes(image)
    return backup


def main() -> int:
    parser = argparse.ArgumentParser(description="Auditable AwesomeWotLK loader patcher for WoW 3.3.5a build 12340.")
    parser.add_argument("--wow", required=True, help="path to Wow.exe")
    parser.add_argument("--original", help="clean Wow.exe, required only for --reset-old-patch or full cave restore")
    parser.add_argument("--expect-sha256", help="refuse to patch if current Wow.exe SHA-256 differs")
    parser.add_argument("--dry-run", action="store_true", help="print planned actions without writing")
    parser.add_argument("--status", action="store_true", help="print patch status and exit")
    parser.add_argument("--unpatch", action="store_true", help="remove this loader patch")
    parser.add_argument("--reset-old-patch", action="store_true", help="restore old Awesome patch ranges from --original first")
    args = parser.parse_args()

    wow = Path(args.wow)
    if not wow.is_file():
        raise PatchError(f"Wow.exe not found: {wow}")

    original = Path(args.original).read_bytes() if args.original else None
    before_hash = sha256(wow)
    if args.expect_sha256 and before_hash.lower() != args.expect_sha256.lower():
        raise PatchError(f"SHA-256 mismatch: expected {args.expect_sha256}, got {before_hash}")

    image = bytearray(wow.read_bytes())
    if args.status:
        print(json.dumps({"wow": str(wow), "sha256": before_hash, "status": patch_status(image)}, indent=2))
        return 0

    if args.unpatch:
        actions = unpatch(image, original)
        backup_prefix = "pre-awesome-unpatch"
    else:
        actions = apply_patch(image, original, args.reset_old_patch)
        backup_prefix = "pre-awesome-patch"

    after_hash = hashlib.sha256(image).hexdigest()
    report = {
        "wow": str(wow),
        "dry_run": args.dry_run,
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "actions": actions,
    }

    if not args.dry_run:
        report["backup"] = str(write_image(wow, image, backup_prefix))

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
