<div align="center">

# LibFPrint with FPC 10a5:a920 Driver Support

*LibFPrint fork providing production-ready match-on-host support for **FPC 10a5:a920** fingerprint sensors.*

<br/>

[![Build packages](https://github.com/feraxtx/libfprint-10a5-a920/actions/workflows/build.yml/badge.svg)](https://github.com/feraxtx/libfprint-10a5-a920/actions/workflows/build.yml)
[![License: LGPL 2.1](https://img.shields.io/badge/License-LGPL2.1-015d93.svg?style=flat-square)](./COPYING)

</div>

---

## Supported Devices

| USB ID | Vendor / Model | Laptop Models | Driver | Matching Engine |
|---|---|---|---|---|
| `10a5:a920` | FPC (Fingerprint Cards AB) Disum | HONOR HGE-WX6, MagicBook, Huawei MateBook | `fpc1022` | SIGFM (SIFT Keypoints) |

---

## Features

- **TLS 1.2 PSK Client**: End-to-end encrypted session over USB using NIST SP 800-108 KDF and AES-256-CBC sealed key derivation.
- **SIGFM Matching**: Reliable match-on-host keypoint detection tuned for 64x176 capacitive sensors with 2x nearest-neighbor upscaling.
- **Power Management & Autosuspend**: Full integration with `udev` and `hwdb` autosuspend rules.
- **Continuous Operation**: Thermal model configured for continuous operation without spurious overheating timeouts.
- **Cryptographic Memory Hygiene**: Automatic cleansing of sensitive keys and PSKs with `OPENSSL_cleanse()`.

---

## Quick Installation

### Fedora (40, 41, 42, 43, 44)

#### Option A: Direct Build & System Install
```bash
# Install build dependencies
sudo dnf install -y gcc gcc-c++ meson ninja-build glib2-devel libgusb-devel \
    pixman-devel systemd-devel libgudev-devel openssl-devel opencv-devel cairo-devel \
    gobject-introspection-devel

# Configure build with Fedora paths
meson setup --reconfigure builddir --prefix=/usr --libdir=/usr/lib64

# Compile and run test suite
meson compile -C builddir
meson test -C builddir

# Install to system
sudo meson install -C builddir

# Restart fprintd daemon
sudo systemctl restart fprintd
```

#### Option B: Build Native RPM Package
```bash
bash .github/scripts/build-rpm.sh
sudo dnf install -y artifacts/*/*.rpm
sudo systemctl restart fprintd
```

---

### Arch Linux

```bash
cd packaging/arch
makepkg -si
sudo systemctl restart fprintd
```

---

### Ubuntu / Debian

```bash
# Build native Debian package
bash .github/scripts/build-deb.sh
sudo dpkg -i artifacts/*/*.deb
sudo systemctl restart fprintd
```

---

## Enrolling & Verifying Fingerprints

1. **Enroll your fingerprint** (supports multiple stages for high accuracy):
   ```bash
   fprintd-enroll "$USER" -f right-index-finger
   ```
   *Follow the terminal prompts, lifting and placing your finger on the sensor for each stage until completed.*

2. **Verify your fingerprint**:
   ```bash
   fprintd-verify "$USER"
   ```

3. **Enable PAM Authentication (Optional)**:
   On Fedora:
   ```bash
   sudo authselect enable-feature with-fingerprint
   sudo authselect apply-changes
   ```
   Now `sudo`, lockscreen, and GDM login will prompt for fingerprint authentication.

---

## Troubleshooting & Verification

- **Check daemon status**:
  ```bash
  systemctl status fprintd
  ```

- **Live debug logs**:
  ```bash
  G_MESSAGES_DEBUG=all sudo /usr/libexec/fprintd
  ```

- **Rollback to standard system library**:
  * On Fedora: `sudo dnf reinstall -y libfprint`
  * On Arch: `sudo pacman -S extra/libfprint`
  * On Ubuntu: `sudo apt install --reinstall libfprint-2-2`
  Then restart `fprintd`: `sudo systemctl restart fprintd`.

---

## License

This project is licensed under the [GNU Lesser General Public License v2.1 or later](./COPYING).
Contains components from NIST NBIS and Bozorth3 under US export-controlled public research distributions.
