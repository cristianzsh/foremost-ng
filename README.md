# foremost-ng

`foremost-ng` is a Linux-based file recovery tool that extracts files from disk images or devices by scanning for configurable file headers and footers. It supports common forensic formats (e.g., `.dd`, Safeback, Encase) and can operate on both image files and live devices.
> ⚡ This fork aims to modernize the codebase, improve terminal output with ANSI styling, and introduce new features for forensic analysis and data recovery.

<img src="screenshots/foremost-ng-01.png"/>
<img src="screenshots/foremost-ng-02.png"/>

---

## Features

- 🧩 Recover files based on headers and footers.
- ⚙️ Configurable file signatures via a plain-text configuration file.
- 🪛 Supports header-only or header–footer scans.
- 🧱 Works on forensic images or live drives.
- 🦠 VirusTotal lookup by file hash (requires a VT API key).

---

## Installation

Clone or download the `foremost-ng` archive, then build and install according to your platform:

```bash
# Common steps
tar xzvf foremost-ng-<version>.tar.gz
cd foremost-ng-<version>/src
```

### Linux
```bash
make
sudo make install
```

### BSD

Make sure ```curl``` is installed:
```bash
pkg_add curl # OpenBSD
pkg install curl # FreeBSD
```

```bash
make unix
sudo gmake install
```

### macOS

Install OpenSSL:
```bash
brew install openssl@3
```

```bash
make mac
sudo make macinstall
```

### Cross compiling for Windows

Install MinGW in your Linux distribution and cross-compile:
```bash
make cross
```
**Required DLLs can be found in the [windows_dlls](windows_dlls) directory of this repository.**

> **Note:** On systems with glibc < 2.2.0, you may see harmless warnings about `ftello` and `fseeko`. These can be safely ignored.

---

## Usage

Run `foremost-ng` with the appropriate command-line options. For full details, refer to the manual page:

```bash
man foremost-ng
```

Basic syntax:
```bash
foremost-ng [options] [image_or_device]
```

---

## VirusTotal API

`foremost-ng` supports automatic file reputation checks using the VirusTotal API via the ```-x``` command-line option. This allows you to analyze recovered files for potential threats by submitting their hashes to VirusTotal.

To enable this feature, follow these steps:

1. [Create a free VirusTotal account](https://www.virustotal.com/gui/join-us).
2. Obtain your personal **API key**.
3. Set the key as an environment variable named `VT_API_KEY`.

```bash
# Unix-like systems
export VT_API_KEY=yourkey

# Windows CMD
set VT_API_KEY=yourkey

# Windows PowerShell
$env:VT_API_KEY="yourkey"
```

---

## Uninstallation

To remove `foremost-ng` from your system:

```bash
cd foremost-ng-<version>/src
sudo make uninstall
```
