# SBOM delta

- baseline: `results/sbom-source.spdx.json` (93 packages)
- result:   `results/sbom-disk.spdx.json` (1244 packages)

| | count |
|---|---|
| added | 1152 |
| removed | 1 |
| version changed | 8 |
| unchanged | 84 |

## By ecosystem

| ecosystem | baseline | result | added | removed |
|---|---|---|---|---|
| deb | 92 | 209 | 117 | 0 |
| oci | 1 | 0 | 0 | 1 |
| generic | 0 | 1012 | 1012 | 0 |
| maven | 0 | 1 | 1 | 0 |
| none | 0 | 1 | 1 | 0 |
| pypi | 0 | 21 | 21 | 0 |

## Added `pkg:deb` packages, by function

### kernel (8)

- `initramfs-tools` 0.142ubuntu25.8
- `initramfs-tools-bin` 0.142ubuntu25.8
- `initramfs-tools-core` 0.142ubuntu25.8
- `kmod` 31+20240202-2ubuntu7.2
- `linux-base` 4.5ubuntu9+24.04.2
- `linux-image-6.8.0-138-generic` 6.8.0-138.138
- `linux-image-virtual` 6.8.0-138.138
- `linux-modules-6.8.0-138-generic` 6.8.0-138.138

### bootloader (4)

- `grub-common` 2.12-1ubuntu7.3
- `grub-efi-amd64` 2.12-1ubuntu7.3
- `grub-efi-amd64-bin` 2.12-1ubuntu7.3
- `grub2-common` 2.12-1ubuntu7.3

### init (10)

- `dbus` 1.14.10-4ubuntu4.1
- `dbus-bin` 1.14.10-4ubuntu4.1
- `dbus-daemon` 1.14.10-4ubuntu4.1
- `dbus-session-bus-common` 1.14.10-4ubuntu4.1
- `dbus-system-bus-common` 1.14.10-4ubuntu4.1
- `init` 1.66ubuntu1
- `systemd` 255.4-1ubuntu8.17
- `systemd-dev` 255.4-1ubuntu8.17
- `systemd-sysv` 255.4-1ubuntu8.17
- `udev` 255.4-1ubuntu8.17

### networking (6)

- `iproute2` 6.1.0-1ubuntu6.4
- `netplan-generator` 1.1.2-8ubuntu1~24.04.2
- `netplan.io` 1.1.2-8ubuntu1~24.04.2
- `openssh-client` 1:9.6p1-3ubuntu13.18
- `openssh-server` 1:9.6p1-3ubuntu13.18
- `openssh-sftp-server` 1:9.6p1-3ubuntu13.18

### cloud-init (27)

- `cloud-guest-utils` 0.33-1
- `cloud-init` 26.1-0ubuntu1~24.04.1
- `python3-apt` 2.7.7ubuntu5.2
- `python3-attr` 23.2.0-2
- `python3-blinker` 1.7.0-1
- `python3-certifi` 2023.11.17-1
- `python3-cffi-backend` 1.16.0-2build1
- `python3-chardet` 5.2.0+dfsg-1
- `python3-configobj` 5.0.8-3
- `python3-cryptography` 41.0.7-4ubuntu0.4
- `python3-debconf` 1.5.86ubuntu1
- `python3-idna` 3.6-2ubuntu0.2
- `python3-jinja2` 3.1.2-1ubuntu1.3
- `python3-json-pointer` 2.0-0ubuntu1
- `python3-jsonpatch` 1.32-3
- `python3-jsonschema` 4.10.3-2ubuntu1
- `python3-jwt` 2.7.0-1ubuntu0.1
- `python3-markupsafe` 2.1.5-1build2
- `python3-minimal` 3.12.3-0ubuntu2.1
- `python3-netplan` 1.1.2-8ubuntu1~24.04.2
- `python3-oauthlib` 3.2.2-1
- `python3-pkg-resources` 68.1.2-2ubuntu1.2
- `python3-pyrsistent` 0.20.0-1build2
- `python3-requests` 2.31.0+dfsg-1ubuntu1.1
- `python3-serial` 3.5-2
- `python3-urllib3` 2.0.7-1ubuntu0.7
- `python3-yaml` 6.0.1-2build2

### dependency (62)

- `adduser` 3.137ubuntu1
- `busybox-initramfs` 1:1.36.1-6ubuntu3.1
- `ca-certificates` 20260601~24.04.1
- `cpio` 2.15+dfsg-1ubuntu2.1
- `dhcpcd-base` 1:10.0.6-1ubuntu3.2
- `distro-info-data` 0.72-0ubuntu0.24.04.1
- `dracut-install` 060+5-1ubuntu3.3
- `ethtool` 1:6.7-1build1
- `fdisk` 2.39.3-9ubuntu6.6
- `gettext-base` 0.21-14ubuntu2
- `klibc-utils` 2.0.13-4ubuntu0.2
- `libapparmor1` 4.0.1really4.0.1-0ubuntu0.24.04.7
- `libargon2-1` 0~20190702+dfsg-4build1
- `libbpf1` 1:1.3.0-2build2
- `libbrotli1` 1.1.0-2build2
- `libbsd0` 0.12.1-1build1.1
- `libcap2-bin` 1:2.66-5ubuntu2.4
- `libcbor0.10` 0.10.2-1.2ubuntu2
- `libcryptsetup12` 2:2.7.0-1ubuntu4.2
- `libdbus-1-3` 1.14.10-4ubuntu4.1
- `libdevmapper1.02.1` 2:1.02.185-3ubuntu3.2
- `libedit2` 3.1-20230828-1build1
- `libefiboot1t64` 38-3.1build1
- `libefivar1t64` 38-3.1build1
- `libelf1t64` 0.190-1.1ubuntu0.1
- `libexpat1` 2.6.1-2ubuntu0.4
- `libfdisk1` 2.39.3-9ubuntu6.6
- `libfido2-1` 1.14.0-1build3
- `libfreetype6` 2.13.2+dfsg-1ubuntu0.1
- `libfuse3-3` 3.14.0-5build1
- `libglib2.0-0t64` 2.80.0-6ubuntu3.8
- `libgssapi-krb5-2` 1.20.1-6ubuntu2.8
- `libjson-c5` 0.17-1build1
- `libk5crypto3` 1.20.1-6ubuntu2.8
- `libkeyutils1` 1.6.3-3build1
- `libklibc` 2.0.13-4ubuntu0.2
- `libkmod2` 31+20240202-2ubuntu7.2
- `libkrb5-3` 1.20.1-6ubuntu2.8
- `libkrb5support0` 1.20.1-6ubuntu2.8
- `libmnl0` 1.0.5-2build1
- `libnetplan1` 1.1.2-8ubuntu1~24.04.2
- `libpng16-16t64` 1.6.43-5ubuntu0.6
- `libpython3-stdlib` 3.12.3-0ubuntu2.1
- `libpython3.12-minimal` 3.12.3-1ubuntu0.16
- `libpython3.12-stdlib` 3.12.3-1ubuntu0.16
- `libreadline8t64` 8.2-4build1
- `libsqlite3-0` 3.45.1-1ubuntu2.7
- `libsystemd-shared` 255.4-1ubuntu8.17
- `libwrap0` 7.6.q-33
- `libxtables12` 1.8.10-3ubuntu2
- `libyaml-0-2` 0.2.5-1build1
- `media-types` 10.1.0
- `netbase` 6.4
- `openssl` 3.0.13-0ubuntu3.15
- `python-apt-common` 2.7.7ubuntu5.2
- `python3` 3.12.3-0ubuntu2.1
- `python3.12` 3.12.3-1ubuntu0.16
- `python3.12-minimal` 3.12.3-1ubuntu0.16
- `readline-common` 8.2-4build1
- `sudo` 1.9.15p5-3ubuntu5.24.04.2
- `tzdata` 2026c-0ubuntu0.24.04.1
- `ucf` 3.0043+nmu1

## Version changed

| package | from | to |
|---|---|---|
| `bsdutils` | 1:2.39.3-9ubuntu6.5 | 1:2.39.3-9ubuntu6.6 |
| `libblkid1` | 2.39.3-9ubuntu6.5 | 2.39.3-9ubuntu6.6 |
| `libmount1` | 2.39.3-9ubuntu6.5 | 2.39.3-9ubuntu6.6 |
| `libsmartcols1` | 2.39.3-9ubuntu6.5 | 2.39.3-9ubuntu6.6 |
| `libssl3t64` | 3.0.13-0ubuntu3.12 | 3.0.13-0ubuntu3.15 |
| `libuuid1` | 2.39.3-9ubuntu6.5 | 2.39.3-9ubuntu6.6 |
| `mount` | 2.39.3-9ubuntu6.5 | 2.39.3-9ubuntu6.6 |
| `util-linux` | 2.39.3-9ubuntu6.5 | 2.39.3-9ubuntu6.6 |

## Removed

- `source` sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
