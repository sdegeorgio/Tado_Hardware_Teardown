# Tado Wireshark Dissector
## Introduction

This is a Wireshark dissector plugin for the Tado wireless central heating control system's 868 MHz over-the-air protocol.
It decodes frames captured by a TI CC1310 sub-1GHz launchpad board loaded with sniffer firmware via the TI-RPI Wireshark plugin.

See [Tado Protocol](../Tado_Protocol.md) for a detailed breakdown of the protocol.

## Packet Sniffer Hardware

Instructions on how to begin capturing OTA packets using the CC1310 launchpad hardware is here: [TI Packet Sniffer 2](https://github.com/sdegeorgio/Tado_Hardware_Teardown/wiki/TI-Packet-Sniffer-2).


## What it decodes

Currently the dissector decodes the PHY / MAC layer framing including CRC and these frames: 

| Frame | Description |
|---|---|
| SYNC | Coordinator beacon — target device + poll countdown |
| Unicast | Data frames (payload likely AES-encrypted) |
| Broadcast | Coordinator broadcast frames |
| ACK | Acknowledgement of data frames |

## Prerequisites

The following is required to build the dissector source:
- [Wireshark source](https://gitlab.com/wireshark/wireshark) cloned and fully built (tested against 4.7.x)
- Visual Studio 2022 with C++ on Windows or GCC/Clang on Linux/macOS
- Python 3 (required by Wireshark's build system)

Refer to the [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html/) for setting up the full build environment, including the `wireshark-x64-libs` dependency bundle on Windows.

## Building the dissector source code

The plugin uses Wireshark's in-tree CMake build system. `CMakeListsCustom.txt` lets you register an external plugin directory without modifying the Wireshark source.

### Step 1 — link the repo into the Wireshark plugin tree

`CMakeListsCustom.txt` requires a path relative to the Wireshark source root, so a directory junction on Windows or symlink on Linux/macOS must be created inside `plugins/epan/`:

**Windows (PowerShell as Administrator):**
```powershell
New-Item -ItemType Junction `
    -Path "C:\path\to\wireshark\plugins\epan\tado-dissector" `
    -Target "C:\path\to\this\repo"
```

**Linux / macOS:**
```bash
ln -s /path/to/this/repo /path/to/wireshark/plugins/epan/tado-dissector
```

### Step 2 — register with Wireshark's CMake

Create or edit `<wireshark-src>/CMakeListsCustom.txt` and set `CUSTOM_PLUGIN_SRC_DIR`
to the relative path of the junction/symlink you just created:

```cmake
set(CUSTOM_PLUGIN_SRC_DIR
    plugins/epan/tado-dissector
)
```

### Step 3 — re-run cmake to pick up the plugin

**Windows** — Use the following command to run cmake, substitute the directory names for your system:

```powershell
cmd.exe /c "set WIRESHARK_LIB_DIR=C:\path\to\wireshark-x64-libs && call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsamd64_x86.bat"" && cd /d C:\path\to\wsbuild64 && cmake ."
```

`WIRESHARK_LIB_DIR` must point to the Wireshark dependency bundle (the directory
containing `vcpkg-export-…`). Alternatively set `WIRESHARK_BASE_DIR` to its parent.
`cmake .` runs from the wsbuild64 directory, reads the existing cache,
and does not re-download dependencies.

**Linux / macOS:**
```bash
cd /path/to/wireshark-build
cmake .
```

### Step 4 — build

**Windows:**
```powershell
cmd.exe /c "call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsamd64_x86.bat"" && msbuild ""C:\path\to\wsbuild64\plugins\epan\tado-dissector\tado-dissector.vcxproj"" /p:Configuration=RelWithDebInfo /p:Platform=x64 /p:BuildProjectReferences=false"
```

**Linux / macOS:**
```bash
cd /path/to/wireshark-build
make tado-dissector
```

The DLL/SO is written to:
- Windows: `<wsbuild>\run\RelWithDebInfo\plugins\4.7\epan\tado-dissector.dll`
- Linux: `<wsbuild>/run/plugins/4.7/epan/tado-dissector.so`

### Installation

If Wireshark is configured to run from the build directory the plugin loads automatically.
Otherwise copy the DLL/SO to the Wireshark personal plugins directory:

- Windows: `%APPDATA%\Wireshark\plugins\4.7\epan\`
- Linux: `~/.local/lib/wireshark/plugins/4.7/epan/`

## Naming devices

To resolve Tado device IDs assigned during pairing to custom names for each device you can add your own via the Wireshark preferences UI:

**Edit → Preferences → Protocols → Tado → Device Names**

| Column | Description |
|---|---|
| Device ID | 16-bit ID in hex (e.g. `0x0f42`). Read from the **Source Device** or **Destination Device** sub-field of any data frame. |
| Name | Free-text label (e.g. `Internet Bridge`, `Lounge TRV`). |

Names appear in the packet tree and in any `proto_item` label that shows an address, including the **Destination Address** field of SYNC beacons.

The table is saved to the Wireshark profile directory as `tado_device_names` and loaded automatically on startup.

## Files

| File | Description |
|---|---|
| `packet-tado.c` | Tado protocol dissector |
| `packet-tado.h` | Dissector header |
| `packet-tirpi.c` | TI-RPI meta-header dissector (from TI-RPI plugin v1.8) |
| `plugin.c` | Wireshark plugin entry-point boilerplate |
| `moduleinfo.h` | Plugin version |
| `CMakeLists.txt` | Build definition (Wireshark in-tree CMake) |
