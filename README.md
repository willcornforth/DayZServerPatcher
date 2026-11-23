# DayZServerPatcher

A Windows C++ utility that modifies a copy of `DayZServer_x64.exe` to bypass BattleEye initialisation for controlled local testing.

> [!WARNING]
> This project is for testing and educational purposes only. It modifies a game server executable and may violate the DayZ service terms or interfere with official online services. Do not use the patched executable on public or protected servers. Always follow Bohemia Interactive's terms and obtain appropriate authorisation before patching or hosting software.

## How It Works

The patcher reads `DayZServer_x64.exe` from the current working directory, searches the binary for two known byte signatures, and rewrites specific instructions in memory. It then writes the modified buffer back to the same executable path.

The application identifies:

- A jump instruction in the BattleEye initialisation failure path
- A test instruction used to control the result of the initialisation check

It replaces the relevant instructions with values that allow execution to continue for testing purposes.

## Repository Contents

```text
DayZServerPatcher/
├── main.cpp                      # Binary loading, signature search, and patch logic
├── DayZServerPatcher.vcxproj     # Visual Studio project configuration
└── DayZServer_Patched.exe        # Previously built reference binary

DayZServerPatcher.sln             # Visual Studio solution
LICENSE.txt                       # MIT licence
README.md
```

## Requirements

- Windows
- Visual Studio 2022
- Desktop development with C++ workload
- MSVC v143 toolchain
- A local copy of `DayZServer_x64.exe`

The Visual Studio project targets both Win32 and x64 configurations, although patching is intended for a 64-bit server executable.

## Building

1. Clone the repository:

   ```powershell
   git clone https://github.com/willcornforth/DayZServerPatcher.git
   cd DayZServerPatcher
   ```

2. Open `DayZServerPatcher.sln` in Visual Studio.
3. Select the `x64` platform and a Debug or Release configuration.
4. Build the solution with **Build > Build Solution**.

The built executable will be written to the project output directory configured in Visual Studio.

## Usage

1. Stop the DayZ server process.
2. Make a backup of the original `DayZServer_x64.exe`.
3. Place `DayZServerPatcher.exe` and `DayZServer_x64.exe` in the same directory.
4. Run `DayZServerPatcher.exe` from that directory.

The default executable name is defined in `main.cpp`:

```cpp
const char* FILE_PATH = "DayZServer_x64.exe";
```

The patcher prints discovered offsets and patch progress in a console window. In success mode, it remains open until Enter is pressed and overwrites `DayZServer_x64.exe` in place.

### Example

```text
[+] File Size 0x123456
[#] jge onFail @ 0x1234
[#] test al, al @ 0x5678
[+] jge distance: 0x52
[+] xor al, al: 0x... [0x...]
[+] Done patching! You can close this window...
```

## Back Up and Test Safely

- Keep the original executable and server configuration unchanged for recovery.
- Do not overwrite the only copy of the server binary.
- Verify that your signature offsets match the installed executable version.
- Test only on an isolated server and with files you are authorised to modify.
- Avoid using the output executable for cheating, anti-cheat bypass, or public multiplayer services.

## Signature Searching

The project uses a small wildcard signature parser. Each wildcard is represented by `?`, and byte values are supplied as hexadecimal pairs:

```cpp
findSignature(buffer, "7D 52 48 8D 0D ? ? ? ?")
findSignature(buffer, "84 C0 75 4D 48 8D 15 ? ? ? ?")
```

If a signature is not found correctly, updates to the target executable may require new signatures and updated patch offsets.

## Limitations

- Designed for a specific build or layout of `DayZServer_x64.exe`.
- Uses fixed byte signatures and does not verify executable version or hash.
- Can produce incorrect output if signatures change or match at the wrong location.
- Overwrites the selected file directly and does not create a patched copy automatically.
- Intended for local testing rather than broad or general-purpose server management.

## Licence

This project is licensed under the MIT License. See [`LICENSE.txt`](LICENSE.txt) for details.
