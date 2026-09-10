# SBOM delta

- baseline: `results/sbom-source.spdx.json` (101 packages)
- result:   `results/sbom-disk.spdx.json` (7158 packages)

| | count |
|---|---|
| added | 7058 |
| removed | 1 |
| version changed | 10 |
| unchanged | 90 |

## By ecosystem

| ecosystem | baseline | result | added | removed |
|---|---|---|---|---|
| deb | 87 | 215 | 128 | 0 |
| golang | 13 | 13 | 0 | 0 |
| oci | 1 | 0 | 0 | 1 |
| generic | 0 | 6904 | 6904 | 0 |
| maven | 0 | 1 | 1 | 0 |
| none | 0 | 1 | 1 | 0 |
| pypi | 0 | 24 | 24 | 0 |

## Added `pkg:deb` packages, by function

### kernel (9)

- `initramfs-tools` 0.151ubuntu1
- `initramfs-tools-bin` 0.151ubuntu1
- `initramfs-tools-core` 0.151ubuntu1
- `kmod` 34.2-2ubuntu2
- `linux-base` 4.15ubuntu5
- `linux-image-7.0.0-31-generic` 7.0.0-31.31
- `linux-image-virtual` 7.0.0-31.31
- `linux-main-modules-zfs-7.0.0-31-generic` 7.0.0-31.31+2
- `linux-modules-7.0.0-31-generic` 7.0.0-31.31

### bootloader (4)

- `grub-efi-amd64` 2.14-2ubuntu1
- `grub-efi-amd64-bin` 2.14-2ubuntu1
- `grub-efi-amd64-unsigned` 2.14-2ubuntu1
- `grub2-common` 2.14-2ubuntu2.1

### init (9)

- `dbus` 1.16.2-2ubuntu4
- `dbus-bin` 1.16.2-2ubuntu4
- `dbus-daemon` 1.16.2-2ubuntu4
- `dbus-session-bus-common` 1.16.2-2ubuntu4
- `dbus-system-bus-common` 1.16.2-2ubuntu4
- `init` 1.69
- `systemd` 259.5-0ubuntu3.4
- `systemd-sysv` 259.5-0ubuntu3.4
- `udev` 259.5-0ubuntu3.4

### networking (6)

- `iproute2` 6.19.0-1ubuntu1.1
- `netplan-generator` 1.2-1ubuntu5
- `netplan.io` 1.2-1ubuntu5
- `openssh-client` 1:10.2p1-2ubuntu3.6
- `openssh-server` 1:10.2p1-2ubuntu3.6
- `openssh-sftp-server` 1:10.2p1-2ubuntu3.6

### cloud-init (31)

- `cloud-guest-utils` 0.33-1build1
- `cloud-init` 26.1-0ubuntu3~26.04.1
- `cloud-init-base` 26.1-0ubuntu3~26.04.1
- `python3-apt` 3.1.0ubuntu1.1
- `python3-attr` 25.4.0-1build1
- `python3-bcrypt` 5.0.0-3build1
- `python3-blinker` 1.9.0-2build1
- `python3-certifi` 2026.1.4+ds-1
- `python3-cffi-backend` 2.0.0-3build1
- `python3-chardet` 5.2.0+dfsg-2build1
- `python3-configobj` 5.0.9-1build1
- `python3-cryptography` 46.0.5-1ubuntu2
- `python3-debconf` 1.5.92
- `python3-idna` 3.11-1ubuntu0.1
- `python3-jinja2` 3.1.6-1build1
- `python3-json-pointer` 2.4-4
- `python3-jsonpatch` 1.32-6
- `python3-jsonschema` 4.19.2-6ubuntu2
- `python3-jsonschema-specifications` 2023.12.1-4
- `python3-jwt` 2.10.1-4ubuntu1
- `python3-markupsafe` 3.0.3-1build1
- `python3-minimal` 3.14.3-0ubuntu2
- `python3-netplan` 1.2-1ubuntu5
- `python3-oauthlib` 3.3.1-1build1
- `python3-passlib` 1.9.3-1ubuntu1
- `python3-referencing` 0.36.2-1ubuntu2
- `python3-requests` 2.32.5+dfsg-1ubuntu1
- `python3-rpds-py` 0.27.1-2ubuntu3
- `python3-serial` 3.5-2build1
- `python3-urllib3` 2.6.3-1ubuntu1.1
- `python3-yaml` 6.0.3-1build1

### dependency (69)

- `3cpio` 0.14.0-1ubuntu1
- `adduser` 3.153ubuntu1
- `busybox-initramfs` 1:1.37.0-7ubuntu1
- `ca-certificates` 20260601~26.04.1
- `dhcpcd-base` 1:10.3.0-7
- `distro-info-data` 0.72-0ubuntu0.26.04.1
- `dracut-install` 110-11
- `ethtool` 1:6.19-1
- `fdisk` 2.41.3-3ubuntu2.2
- `gettext-base` 0.23.2-1
- `klibc-utils` 2.0.14-1ubuntu2
- `libapparmor1` 5.0.2-0ubuntu1~26.04.1
- `libatomic1` 16-20260322-1ubuntu1
- `libbpf1` 1:1.6.3-1ubuntu1
- `libbrotli1` 1.2.0-3build1
- `libcap2` 1:2.75-10ubuntu2
- `libcap2-bin` 1:2.75-10ubuntu2
- `libcbor0.10` 0.10.2-2ubuntu3
- `libdbus-1-3` 1.16.2-2ubuntu4
- `libdevmapper1.02.1` 2:1.02.205-2ubuntu3
- `libedit2` 3.1-20251016-1
- `libefiboot1t64` 39-2
- `libefivar1t64` 39-2
- `libelf1t64` 0.194-4
- `libexpat1` 2.7.4-1
- `libfdisk1` 2.41.3-3ubuntu2.2
- `libffi8` 3.5.2-4
- `libfido2-1` 1.16.0-2build1
- `libfreetype6` 2.14.2+dfsg-1ubuntu0.1
- `libfuse3-4` 3.18.2-1
- `libglib2.0-0t64` 2.88.0-1
- `libgssapi-krb5-2` 1.22.1-2ubuntu4.1
- `libjs-sphinxdoc` 8.2.3-12
- `libk5crypto3` 1.22.1-2ubuntu4.1
- `libkeyutils1` 1.6.3-6ubuntu3
- `libklibc` 2.0.14-1ubuntu2
- `libkmod2` 34.2-2ubuntu2
- `libkrb5-3` 1.22.1-2ubuntu4.1
- `libkrb5support0` 1.22.1-2ubuntu4.1
- `libmnl0` 1.0.5-3build1
- `libnetplan1` 1.2-1ubuntu5
- `libpng16-16t64` 1.6.57-1
- `libpython3-stdlib` 3.14.3-0ubuntu2
- `libpython3.14-minimal` 3.14.4-1ubuntu0.2
- `libpython3.14-stdlib` 3.14.4-1ubuntu0.2
- `libreadline8t64` 8.3-4
- `libsqlite3-0` 3.46.1-9ubuntu0.2
- `libsystemd-shared` 259.5-0ubuntu3.4
- `libtext-charwidth-perl` 0.04-11build4
- `libtext-wrapi18n-perl` 0.06-10
- `libtirpc-common` 1.3.7-0.1
- `libtirpc3t64` 1.3.7-0.1
- `libwrap0` 7.6.q-36build2
- `libxtables12` 1.8.11-2ubuntu3
- `libyaml-0-2` 0.2.5-2build3
- `media-types` 14.0.0build1
- `netbase` 6.5build1
- `netcat-openbsd` 1.234-1
- `openssl` 3.5.5-1ubuntu3.5
- `python-apt-common` 3.1.0ubuntu1.1
- `python3` 3.14.3-0ubuntu2
- `python3.14` 3.14.4-1ubuntu0.2
- `python3.14-minimal` 3.14.4-1ubuntu0.2
- `readline-common` 8.3-4
- `sudo` 1.9.17p2-1ubuntu3
- `sudo-common` 1.2ubuntu
- `tzdata` 2026c-0ubuntu0.26.04.1
- `ucf` 3.0052ubuntu1
- `wireless-regdb` 2026.02.04-0ubuntu1

## Version changed

| package | from | to |
|---|---|---|
| `bsdutils` | 1:2.41.3-3ubuntu2 | 1:2.41.3-3ubuntu2.2 |
| `libblkid1` | 2.41.3-3ubuntu2 | 2.41.3-3ubuntu2.2 |
| `libmount1` | 2.41.3-3ubuntu2 | 2.41.3-3ubuntu2.2 |
| `libsmartcols1` | 2.41.3-3ubuntu2 | 2.41.3-3ubuntu2.2 |
| `libssl3t64` | 3.5.5-1ubuntu3.3 | 3.5.5-1ubuntu3.5 |
| `libuuid1` | 2.41.3-3ubuntu2 | 2.41.3-3ubuntu2.2 |
| `login` | 1:4.16.0-2+really2.41.3-3ubuntu2 | 1:4.16.0-2+really2.41.3-3ubuntu2.2 |
| `mount` | 2.41.3-3ubuntu2 | 2.41.3-3ubuntu2.2 |
| `openssl-provider-legacy` | 3.5.5-1ubuntu3.3 | 3.5.5-1ubuntu3.5 |
| `util-linux` | 2.41.3-3ubuntu2 | 2.41.3-3ubuntu2.2 |

## Removed

- `source` sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b
