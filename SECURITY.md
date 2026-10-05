# Dropper security design

Dropper moves files and text between one Windows PC and your phones. It is
built so that **nothing outside your local network can reach it**, and so that
**nothing on your local network can read, alter, inject or impersonate**
transfers, except a device you physically paired.

The exact wire format is in [`docs/PROTOCOL.md`](docs/PROTOCOL.md). This page
covers the threat model and the reasons behind the design.

**Reporting a vulnerability.** Use GitHub's private reporting (*Security* tab →
*Report a vulnerability*) on
[C-Squared-Solutions-LLC/dropper](https://github.com/C-Squared-Solutions-LLC/dropper).
Please don't open a public issue for security problems.

## Threat model

| Adversary | What stops them |
|---|---|
| **Internet attacker** | Dropper never listens on a public interface. **TCP:** it listens only on private IPv4 addresses of *physical* Ethernet/Wi-Fi adapters, and only on networks Windows marks Private or Domain, never Public (cafés, hotels). VPN, Tailscale, WSL, Hyper-V and Docker adapters are excluded, and any peer outside the adapter's subnet is refused. **UDP discovery:** the socket is bound to all interfaces, but it answers only packets that *arrived on* the LAN adapter, *from* its subnet, carrying a paired device's MAC. The firewall rules allow only `LocalSubnet` on Private/Domain networks. There is no cloud relay, account or server. |
| **Someone else on your Wi-Fi** (guest, compromised IoT device, neighbour who cracked the password) | Every connection must open with an HMAC preamble keyed by a paired device's secret before the PC parses a single TLS byte, so unpaired devices get silence. After that comes **TLS 1.3 with mutual authentication**, and both ends pin each other's public key. Discovery packets are HMAC-authenticated too, and the PC never answers strangers. |
| **Active man-in-the-middle on the LAN** (ARP/DHCP spoofing) | Keys are pinned at pairing via the QR code, an out-of-band channel you verify with your eyes, so there is no trust-on-first-use window. A MITM can't present the PC's key to the phone or the phone's key to the PC. While the TLS stack checks the client certificate (before Dropper's pin check), it never downloads anything or consults the machine's trust store. |
| **Someone who photographs or screen-shares the QR code** | The code is valid for 3 minutes, works once, and the PC user must approve the phone after checking that the 6-digit code on both screens matches. A stolen QR yields a pairing request you will see and reject. The pairing window is also excluded from screenshots, recordings and screen sharing. |
| **Replay of captured traffic** | TLS 1.3 itself prevents replay. The plaintext preamble and discovery packets carry a timestamp (±10 min) and a random nonce kept in a 20-minute replay cache. |
| **Malicious content** from a compromised phone | Received names are sanitized: path traversal, `CON`/`NUL` device names, and every invisible or format code point (bidi "RLO" spoofing, zero-width, soft hyphen, tag characters, Hangul fillers). Shortcut-like files (`.lnk`, `.url`, `.scf`, `.library-ms`, `desktop.ini`, …), which Windows acts on just by showing a folder, are renamed. This is checked on the *final* name, after length capping. Files are written to a hidden temp file, SHA-256-checked, tagged with **Mark-of-the-Web**, and only then renamed into view, so SmartScreen and Office Protected View apply. If the destination can't hold the tag (FAT/exFAT, some shares), Dropper says so and won't offer to open the file. It never offers to open programs or scripts at all. Nothing is ever auto-opened. Only plain `http(s)` links get an Open button. |
| **A malicious app on your phone** (no special permissions) | Any app can open Dropper's share screen, so the screen first shows exactly what would be sent and does nothing until you tap **Send**. An app therefore can't silently push files or clipboard text to your PC. |
| **Theft of key files** (backup, disk image, another Windows account) | Private keys are non-exportable and hardware-backed. On the PC the key lives in the **TPM** (with a fallback to the DPAPI-protected Windows key store); on the phone it lives in the **Android Keystore** (TEE). Per-device secrets and history are encrypted at rest (DPAPI / Keystore AES-GCM). Android backup is disabled. The Android release-signing key is kept outside the source tree (`%USERPROFILE%\.dropper\signing`). |
| **Leaks through the clipboard** | Text auto-copied from the phone is flagged so Windows keeps it out of Clipboard History and Cloud Clipboard sync; Android marks it sensitive. |
| **Denial of service on the LAN** | At most 16 unauthenticated connections, 2 per address. When full, the *oldest* pending connection is dropped, so a flood only pushes out its own entries. A connection must greet within 3 s. Silent, truncated or invalid greetings all count toward a 5-minute per-address lock-out (10 failures per minute). Discovery is rate-limited, survives malformed packets, and its responses are smaller than requests (no amplification). The TPM signs only for peers that present a valid HMAC preamble, i.e. ones holding a device or pairing secret. The single exception is a preamble captured in the 10 minutes before a PC restart (the replay cache lives in memory), and that still fails TLS. Refusals are logged at most once per minute per address, and the log is size-capped. |

### Out of scope

- **Malware running as you on the PC, or as root on the phone.** It can use
  Dropper the way you can, and read files you received. Hardware-backed keys
  stop it from *copying* the identity key off the device, but not from using it
  while it runs there.
- **Physical access to an unlocked device.**
- **Traffic analysis.** Someone on the LAN can see *that* your phone and PC
  talk on port 47823, and roughly how many bytes move, but not what they are.

## Cryptography

| Purpose | Mechanism |
|---|---|
| Device identity | ECDSA P-256 key pair. Fingerprint = SHA-256 of the SubjectPublicKeyInfo. |
| Transport | TLS 1.3 only (AES-GCM / ChaCha20-Poly1305, ECDHE so every session has forward secrecy). Mutual certificate authentication with exact public-key pinning. Session resumption disabled, so every connection is a full handshake. |
| Pairing | 256-bit one-time secret inside the QR code, with keys derived by HKDF-SHA256. An HMAC proof binds the secret to *both* TLS public keys. A 6-digit SAS (short authentication string) is compared by the user. |
| PC-to-PC pairing | Numeric comparison with a commitment, as in Bluetooth Secure Simple Pairing. The host sends `SHA-256(Na ‖ fp_host ‖ fp_joiner)` before it sees the joiner's `Nb`. The 6-digit code is HMAC'd from `HKDF(Na ‖ Nb)` over both TLS fingerprints, and both users must approve. |
| Pre-TLS gate | HMAC-SHA256 under a per-device key (HKDF from a 256-bit secret created when you approve pairing), plus timestamp and nonce. |
| Discovery | HMAC-SHA256 request and response under a separate per-device key. |
| Content integrity | SHA-256 of every item, checked end to end, on top of TLS's own AEAD. |

Randomness comes only from the OS CSPRNG. MAC and proof comparisons are
constant-time.

## Why it's built this way

- **No home-made transport crypto.** Confidentiality and authentication come
  from TLS 1.3 as implemented by Windows (SChannel) and Android (Conscrypt).
  Dropper adds pinning and two small MAC checks on top, which is a few lines
  each and easy to audit.
- **Silence before TLS** follows the same idea as WireGuard's "don't respond to
  strangers" and OpenVPN's `tls-auth`. Bugs in a TLS stack's handshake parser
  are a recurring vulnerability class. Here only devices holding a pairing
  secret ever reach that parser.
- **Out-of-band pairing instead of trust-on-first-use.** The QR code carries
  the PC's exact public key, so the phone never has to "accept a certificate".
  The 6-digit comparison covers the remaining case of someone else scanning the
  code first.
- **Two PCs have no camera between them.** They compare a 6-digit code instead.
  A man in the middle sees a different fingerprint pair on each side, so to fool
  both users it has to make two codes collide. Because of the commitment,
  neither side can choose its nonce after seeing the other's. The attacker gets
  one blind guess per attempt (10⁻⁶), each attempt needs both users to approve,
  and 5 failures close the window.
- **The PC-pairing window is the one time the gate is open.** Two PCs share no
  secret before pairing, so the mode-3 preamble uses a public key. For up to
  3 minutes after you click *Let another PC find this one*, any host on the LAN
  subnet can reach the TLS handshake and see the PC's name in a discovery reply.
  Only one attempt runs at a time. The per-IP throttle and the pre-auth limits
  still apply, and nothing gets stored without both approvals. Outside that
  window, mode 3 is refused before TLS, like any other bad preamble.
- **Minimal dependencies.** The Windows app uses only the .NET base library plus
  QRCoder (to draw the QR code). The Android app uses AndroidX, Jetpack Compose
  and ZXing (to read the QR code). Neither app uses third-party networking or
  crypto libraries.

## How this is tested

- `tools/gen_test_vectors.py` is an independent Python implementation of the
  key schedule and packet formats. Both apps' unit tests must reproduce its
  `docs/test-vectors.json` byte for byte, plus RFC 5869 test case 3 for HKDF.
- The Windows test suite runs a real engine against a fake phone on loopback.
  It checks that:
  - wrong-key, replayed, stale and plain-TLS connections get **zero bytes**
    back;
  - a valid gate with the wrong TLS key is refused;
  - the phone refuses a PC with a different key;
  - bad pairing proofs are refused, and five of them close the window;
  - a rejected pairing creates no device;
  - unpairing sends `BYE` and locks the phone out;
  - discovery stays silent to strangers and doesn't amplify;
  - corrupted transfers are discarded;
  - hostile file names are sanitized and Mark-of-the-Web is applied;
  - every finding from the independent review stays fixed (truncation bypass,
    invisible code points, overflowing timestamps, idle-connection floods,
    lock-out after bad greetings, tag-before-rename);
  - two real engines pair PC to PC only when both sides approve, compute the
    same code, and transfer both ways afterwards. A rejection on either side
    stores nothing. A PC with no open window can't be found or paired. Removing
    the pairing on one PC removes it on the other. The commitment binds the nonce
    and both keys.
- End-to-end runs pair the **real Android app** (emulator) with the **real
  Windows app**, through the actual UIs:
  - both screens showed the same 6-digit code;
  - text, links and files moved both ways with matching SHA-256;
  - removing the phone on the PC returned the phone to its pairing screen
    immediately, and unpairing on the phone made the PC forget it;
  - a share launched directly by another app waited for **Send** and sent
    nothing on **Cancel**.

## Independent review

A separate reviewer audited both codebases against this document. It found no
Critical or High issues, and nothing that lets an unpaired device bypass
authentication, intercept traffic or inject transfers. It reported six edge
issues (two Medium, the rest Low), all fixed and covered by tests:

| Finding | Fix |
|---|---|
| A length cap could expose an inner `.lnk` extension | Shell-trigger checks run on the final name; `desktop.ini`, `autorun.inf` and `.pif` were added |
| Any phone app could push content without consent | The share screen requires an explicit **Send** with a preview |
| A crafted timestamp overflowed `Math.Abs` and stopped discovery | Overflow-free freshness check; the discovery loop survives any packet |
| Idle connections could hold every pre-auth slot | Per-address cap, oldest-first eviction, silent greetings count as failures |
| Mark-of-the-Web could be silently missing | Tagged before the rename; untagged files and executables are never offered for opening |
| Received text reached Clipboard History and Cloud Clipboard | Excluded through the documented clipboard formats |

Hardening it also suggested is in place too:
- no certificate downloads during TLS;
- firewall rules written through the COM API by an elevated copy of the app,
  instead of a `cmd` string;
- absolute system paths;
- the pairing window is hidden from screen capture;
- the unpair/reconnect race is closed;
- networks marked Public are refused;
- the Android signing key was moved out of the source tree.

## Recovering from a lost phone or exposed key

- **Lost phone:** Dropper (PC) → Settings → Paired phones → *Remove*. It is
  locked out immediately (a reconnect racing the removal is refused too), and
  any open connection is closed with `BYE`.
- **PC key exposed:** Settings → Security → *Reset identity*. A new key is
  created and every phone must pair again.
- **Phone:** Settings → *Unpair* wipes the pairing, the secrets and the
  phone's identity key. If the PC is reachable, it is told and forgets the
  phone too. Uninstalling the app also destroys its Keystore key.
