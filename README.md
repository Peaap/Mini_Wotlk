# AwesomeWotLK Trusted Patcher

This folder contains the repo-owned patcher for loading `AwesomeWotlkLib.dll`
after the client's native extension scan succeeds.

The patcher is intentionally boring:

- source-visible Python, no packed executable
- prints SHA-256 before and after patching
- refuses unknown hook bytes unless explicitly migrating with a clean original
- creates a timestamped backup before writing
- supports `--dry-run`, `--status`, and `--unpatch`


## Patch

Check status first:

```powershell
python .\tools\patch_wow.py --wow [Wow.exe PATH] --status
```

Dry run:

```powershell
python .\tools\patch_wow.py --wow [Wow.exe PATH] --dry-run
```

Apply:

```powershell
python .\tools\patch_wow.py --wow [Wow.exe PATH]
```

For a repo release, publish the expected input hash and require it:

```powershell
python .\tools\patch_wow.py --wow [Wow.exe PATH] --expect-sha256 <known-clean-sha256>
```

## Bytes Written

The loader hook is written at `0x004E5E97`, the successful return path of
native `ScanDllStart`. It preserves the displaced instruction, calls the
client's internal DLL loader at `0x0086C4E0`, and loads:

```text
AwesomeWotlkLib.dll
```

The code cave begins at `0x009DE3C0`. The patcher also enables the PE
`IMAGE_FILE_LARGE_ADDRESS_AWARE` flag.
