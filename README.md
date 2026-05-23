# AwesomeWotLK Trusted Patcher

This folder contains the repo-owned patcher for loading `AwesomeWotlkLib.dll`
after the client's native extension scan succeeds.

The patcher is intentionally boring:

- source-visible Python, no packed executable
- prints SHA-256 before and after patching
- refuses unknown hook bytes unless explicitly migrating with a clean original
- creates a timestamped backup before writing
- supports `--dry-run`, `--status`, and `--unpatch`

## Build

Build the x86 release DLL with MSVC:

```powershell
$vs = 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat'
cmd /c "call `"$vs`" -arch=x86 -host_arch=x64 && cmake --build build-codex-x86 --config Release -j 8 --target AwesomeWotlkLib"
```

Copy the DLL next to `Wow.exe`:

```powershell
Copy-Item .\build\Release\AwesomeWotlkLib.dll D:\Wotlk\AwesomeWotlkLib.dll -Force
```

## Patch

Check status first:

```powershell
python .\tools\patch_wow.py --wow D:\Wotlk\Wow.exe --status
```

Dry run:

```powershell
python .\tools\patch_wow.py --wow D:\Wotlk\Wow.exe --dry-run
```

Apply:

```powershell
python .\tools\patch_wow.py --wow D:\Wotlk\Wow.exe
```

For a repo release, publish the expected input hash and require it:

```powershell
python .\tools\patch_wow.py --wow D:\Wotlk\Wow.exe --expect-sha256 <known-clean-sha256>
```

## Migrating From Another Awesome Patch

If the executable was already modified by an older patcher, provide a clean
backup and allow the patcher to restore the old Awesome patch ranges first:

```powershell
python .\tools\patch_wow.py --wow D:\Wotlk\Wow.exe --original D:\Wotlk\Wow.clean.exe --reset-old-patch
```

## Unpatch

```powershell
python .\tools\patch_wow.py --wow D:\Wotlk\Wow.exe --unpatch
```

Passing `--original` during unpatch also restores the unused code-cave bytes.

## Bytes Written

The loader hook is written at `0x004E5E97`, the successful return path of
native `ScanDllStart`. It preserves the displaced instruction, calls the
client's internal DLL loader at `0x0086C4E0`, and loads:

```text
AwesomeWotlkLib.dll
```

The code cave begins at `0x009DE3C0`. The patcher also enables the PE
`IMAGE_FILE_LARGE_ADDRESS_AWARE` flag.
