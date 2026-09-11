# Tutorial — ship a VM appliance someone else can trust

## The scenario

Someone sends you a 600MB `appliance.ova`. Even though it runs, you question:

- What exactly is inside it?
- Who built it, and from what?
- Has anything changed since they built it?
- How much did the conversion add?

With a random VM, you have to answer these by simply believing the person that sent you the disk.

This tutorial produces a disk where you can answer everything from the artifact itself without even downloading it.

You will build a real service appliance from your own Dockerfile, publish it, verify it from a second machine, boot it with the credentials that the second machine chooses, and then tamper with it and watch the verification fail.

Prerequisites: [requirements.md](requirements.md), and a registry you can
push to. Substitute your own namespace for `ghcr.io/you` throughout.

You also need an SSH keypair — the seeds below install the public half in the
guest, and `boot-test` logs in with the private half. If you have no
`~/.ssh/id_ed25519`:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

Leave the passphrase empty: `boot-test` runs `ssh` non-interactively and cannot
answer a prompt.



## 1. The application

```bash
mkdir -p ~/statusd && cd ~/statusd
```

`app.py` — no dependencies, so the package delta stays legible:

```python
import json, platform, socket
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "service": "statusd",
            "host": socket.gethostname(),
            "kernel": platform.release(),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", 8080), H).serve_forever()
```

`statusd.service`:

```ini
[Unit]
Description=statusd
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/statusd/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

`Dockerfile`:

```dockerfile
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
COPY app.py /opt/statusd/app.py
COPY statusd.service /etc/systemd/system/statusd.service
RUN mkdir -p /etc/systemd/system/multi-user.target.wants \
 && ln -s /etc/systemd/system/statusd.service \
          /etc/systemd/system/multi-user.target.wants/statusd.service
```

> **The one thing to understand here.** c2vm converts a container's
> *filesystem*, not its `CMD`. Your entrypoint is ignored — the VM boots
> systemd, not your process. So the image must ship a unit file and enable it
> itself, which is what that `ln -s` does: `systemctl enable` needs a running
> systemd, a symlink does not.

Build and push. c2vm pulls with `skopeo` over `docker://`, so the image has to
be in a registry:

```sh
docker build -t ghcr.io/you/statusd:1 .
docker push    ghcr.io/you/statusd:1
```

---

## 2 · Convert it

```sh
sudo ./c2vm build ghcr.io/you/statusd:1 \
  --kernel linux-image-amd64 \
  --hostname statusd \
  --format qcow2,ova \
  --out build-statusd

sudo chown -R $USER:$USER build-statusd
```

`--kernel linux-image-amd64` because the base is Debian; on Ubuntu bases the
default `linux-image-virtual` is right.

Read `build-statusd/metadata/build.json`. Every decision the build made is in
there, including the source image digest it pinned — note that it recorded the
**digest**, not the tag you typed. That is the first link of the chain.

---

## 3 · Prove it boots

No `--ssh-key`: an appliance you hand to someone else must not carry your key.
`boot-test` gets in with a throwaway seed instead, which is the same mechanism
the recipient will use in step 7.

```sh
mkdir -p testseed
printf '#cloud-config\nusers:\n  - name: c2vm\n    groups: [adm, sudo]\n    shell: /bin/bash\n    sudo: "ALL=(ALL) NOPASSWD:ALL"\n    ssh_authorized_keys:\n      - "%s"\n' \
  "$(cat ~/.ssh/id_ed25519.pub)" > testseed/user-data
echo "instance-id: iid-boot-test" > testseed/meta-data
genisoimage -quiet -output testseed.iso -V cidata -r -J testseed

./c2vm boot-test build-statusd/disk.qcow2 \
  --ssh-key ~/.ssh/id_ed25519 --seed testseed.iso --out build-statusd
```

This boots the disk headless, waits for SSH, and asserts the guest matches
what `build.json` claims: systemd state, root filesystem UUID, an address on
the network, and the kernel version. It runs with `-snapshot`, so the disk's
hash survives the test.

Confirm the service actually came up:

```sh
cp /usr/share/OVMF/OVMF_VARS_4M.fd /tmp/statusd-vars.fd
qemu-system-x86_64 -machine q35 -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=/tmp/statusd-vars.fd \
  -drive file=build-statusd/disk.qcow2,format=qcow2,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
  -device virtio-net-pci,netdev=net0 \
  -display none -serial file:/tmp/statusd.log -no-reboot -snapshot &

sleep 45 && curl -s localhost:8080 | jq .
```

Expect your JSON, with the guest's hostname and the kernel c2vm installed.

---

## 4 · Measure what the conversion cost you — the part nobody else does

```sh
sudo ./c2vm scan build-statusd/disk.qcow2 \
  --out build-statusd --results results-statusd
sudo chown -R $USER:$USER results-statusd

./c2vm sbom-diff results-statusd/sbom-source.spdx.json \
                 results-statusd/sbom-disk.spdx.json --results results-statusd
./c2vm cve-diff  results-statusd/cve-source.json \
                 results-statusd/cve-disk.json      --results results-statusd
```

Open `results-statusd/sbom-diff.md`. Your image had a handful of packages. The
disk has well over a hundred more — a kernel, an initramfs, GRUB, systemd,
cloud-init, netplan — grouped by *why* each was added.

**This is the number the whole project exists to produce.** You did not
install any of it. It arrived because a container has no kernel and a VM
needs one. Every CVE in `cve-diff.md` that wasn't in your image entered at
this step, and until now nobody measured it.

Read the two columns in `cve-diff.md` before you panic at the totals: the
all-ecosystem column matches the kernel a second time by CPE against NVD,
which reports every CVE ever filed against that version rather than the ones
your distribution has already backported. Gate on the deb column.

---

## 5 · Publish and sign

```sh
./c2vm push   build-statusd/disk.qcow2 ghcr.io/you/statusd-vm:1 --out build-statusd
./c2vm sign   ghcr.io/you/statusd-vm:1
./c2vm attest ghcr.io/you/statusd-vm:1 --out build-statusd --results results-statusd
```

`sign` opens a browser. Sigstore issues a certificate valid for ten minutes,
binds it to the identity you log in with, signs, throws the key away and
records the event in a public append-only log. There is no key for you to
store or leak.

`attest` attaches two signed claims: the SBOM, and a conversion statement
naming the source image digest, the kernel, and every package the conversion
added — the same list `sbom-diff` published, copied verbatim so the signed
claim and the public report cannot disagree.

The disk contains **no credentials** — that is why step 2 passed no
`--ssh-key`. The only login that ever existed was the throwaway seed
`boot-test` mounted, and that seed never touched the disk. Whoever receives it
supplies their own, the same way — see step 7.

---

## 6 · The receiving end

Move to another machine. Install only `cosign`, `oras` and c2vm. You have the
600 MB disk on neither disk nor network — just a string.

```sh
./c2vm verify ghcr.io/you/statusd-vm:1
```

```
==> verifying ghcr.io/you/statusd-vm:1
  identity you@example.com (https://github.com/login/oauth)

  ok   signature                    sha256:…
  ok   sbom attestation             https://spdx.dev/Document
  ok   conversion attestation       https://c2vm.dev/conversion/v1
  ok   disk digest binding          sha256:…
  ok   source image                 sha256:…
  ok   cve policy: critical         5 deb finding(s), limit 5

  ghcr.io/you/statusd:1 -> kernel 6.1.0-…, built 2026-09-10T…Z

all checks passed
```

Six answers to the four questions at the top of this page, from a string.
**The disk was never downloaded** — a manifest and two attestations is a few
hundred kilobytes. Cheap verification is the point: custody nobody can afford
to check is custody nobody checks.

The fourth line is the one that matters. A signature alone covers the
*manifest* — a 700-byte pointer. That check pulls the disk's hash out of the
signed statement and demands it equal the layer the registry is actually
serving.

---

## 7 · Actually use it

The disk has no accounts. You add yours with a cloud-init seed, which
overrides the one baked in at build time:

```sh
oras pull ghcr.io/you/statusd-vm:1

mkdir -p seed
PWHASH=$(openssl passwd -6)

cat > seed/user-data <<EOF
#cloud-config
users:
  - name: ops
    groups: [adm, sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: false
    passwd: "$PWHASH"
    ssh_authorized_keys:
      - "$(cat ~/.ssh/id_ed25519.pub)"
ssh_pwauth: false
EOF

echo "instance-id: iid-$(hostname)-$(date +%s)" > seed/meta-data
genisoimage -output seed.iso -V cidata -r -J seed

cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
qemu-system-x86_64 -machine q35 -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive file=disk.qcow2,format=qcow2,if=virtio \
  -drive file=seed.iso,media=cdrom \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:8080 \
  -device virtio-net-pci,netdev=net0 -nographic -no-reboot

# elsewhere
curl -s localhost:8080 | jq .
ssh -p 2222 ops@127.0.0.1
```

The `.ova` from step 2 imports straight into VirtualBox or VMware for anyone
who wants a click instead of a command line.

---

## 8 · Break it on purpose

A verification you have never seen fail is a verification you have no reason
to believe. Play the attacker: keep the signed claims, swap the bytes.

```sh
cp build-statusd/disk.qcow2 /tmp/evil.qcow2
printf 'x' | dd of=/tmp/evil.qcow2 bs=1 seek=100000000 conv=notrunc

./c2vm push   /tmp/evil.qcow2 ghcr.io/you/statusd-vm:tampered --out build-statusd
./c2vm sign   ghcr.io/you/statusd-vm:tampered
./c2vm attest ghcr.io/you/statusd-vm:tampered \
              --out build-statusd --results results-statusd

./c2vm verify ghcr.io/you/statusd-vm:tampered
```

```
  ok   signature                    sha256:…
  ok   sbom attestation             https://spdx.dev/Document
  ok   conversion attestation       https://c2vm.dev/conversion/v1
  FAIL disk digest binding          sha256:…
  ok   source image                 sha256:…

1 check(s) failed
```

Exit code 3.

Read that carefully. The signature is **valid**. The attestations are
**genuinely signed**, by a **real identity**, over a **real certificate**.
Every check a plain `cosign verify` performs passes. The artifact is still
rejected, because the disk hash in the signed statement is no longer the disk
the registry is serving.

That single line is the difference between "somebody signed something" and
"this artifact is the one that was built". It is why c2vm exists rather than
a shell script around `cosign`.

Clean up the tag when you are done.

---

## What you can now prove — and what you still cannot

**Can prove,** from a reference alone: a named identity published it; the
bytes are unchanged since signing; it came from a specific source image
digest; exactly which packages the conversion added; how many CVEs it carries
under today's data.

**Cannot prove:** that the build machine was honest. Nothing here is
reproducible — you cannot rebuild from the source digest and confirm the same
disk hash. The chain establishes *what the builder claimed*, cryptographically
bound to *these bytes*, by *this identity*. It does not conjure trust from
nothing, and a supply-chain tool that claimed otherwise would be lying to you.
