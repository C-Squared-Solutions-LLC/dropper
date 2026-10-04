# Dropper for Android

The phone half of Dropper. It pairs with the Windows app by QR code. After
that, files, photos, links and text travel in both directions over your local
network only, end-to-end encrypted and mutually authenticated. The wire format
is specified in [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md).

## Install on your phone

The signed release APK is `app/build/outputs/apk/release/app-release.apk` (about 2.4 MB).

**Option A — USB / wireless debugging (recommended):**
1. On the phone, open **Settings › About phone › Software information** and tap
   *Build number* 7× to enable Developer options.
2. Go to **Settings › Developer options** and turn on *USB debugging*, or
   *Wireless debugging* for Wi-Fi.
3. Connect the phone, then run
   `adb install -r app\build\outputs\apk\release\app-release.apk`.

**Option B — copy the APK:** copy the APK to the phone over USB, open it in *My
Files*, and allow *Install unknown apps* for My Files when prompted. Turn that
permission off again afterwards.

Then open Dropper, tap **Scan QR code**, click **Pair a phone** in Dropper on the
PC, scan the code, and approve on the PC once both screens show the same 6-digit
code.

> **Signing.** Updates must be signed with the same key. The key and its password
> file live outside the project, in `%USERPROFILE%\.dropper\signing\`
> (`dropper-release.jks`, `keystore.properties`), so they can never be committed or
> zipped up with the source. Set `DROPPER_SIGNING_DIR` to use another folder.
> **Back that folder up.** Debug and release builds use different keys, so you
> have to uninstall one before installing the other.

## Security on the phone side

| | |
|---|---|
| Identity key | EC P-256 in Android Keystore (TEE on the S23), non-exportable. Settings shows its storage level. A new key is generated at the first pairing, and again after you unpair. |
| Transport | TLS 1.3 only, mutual auth, fresh `SSLContext` per connection (no resumption). Trusts exactly one key: the PC's SPKI pin from the QR code. The pin is checked in the TrustManager and again on the finished session. |
| Before TLS | A 61-byte HMAC preamble (gate key from the device secret) is sent, so the PC never exposes its TLS stack to unpaired devices. |
| Secrets at rest | The device secret, pairing record, history and outbox index are AES-256-GCM encrypted with a Keystore key (`secure/*.bin`). Each file is bound to its name through the associated data. Copies of files waiting to be sent sit unencrypted in the app sandbox (`files/outbox/`, protected by Android's file-based encryption) and are deleted once delivered. |
| Network scope | Only Wi-Fi or Ethernet networks, never cellular. Sockets are bound to that network when Android allows it. A VPN that forbids bypassing can force the default route, but the PC's pinned key still protects the connection. Destinations must be RFC 1918 IPv4. |
| Discovery | Authenticated UDP request/response (§10); unauthenticated replies are ignored. |
| Received content | Names are sanitized (path components, reserved names, control/bidi characters, length). Files are saved to `Download/Dropper` via MediaStore and stay hidden while pending until the hash verifies. MIME type comes from the extension, not from the peer. Nothing is ever auto-opened. Links get an *Open* button only when the whole text is one http(s) URL. |
| Share target | Any app can open the share screen, so it first shows what would be sent and does nothing until you tap **Send**. It accepts only `content://` URIs from other apps; `file://` and Dropper's own providers are refused. Confirmed content is copied into app-private storage, then sent. |
| App hardening | No backup or device transfer (`allowBackup=false` + data-extraction rules). Cleartext is disabled. The only exported components are the launcher, the share target and the boot receiver. All PendingIntents are immutable. Release builds strip `Log.d/i/v`. |
| Supply chain | Few dependencies: AndroidX/Compose, coroutines, and ZXing for on-device QR decoding. No networking or crypto libraries. Gradle distribution SHA-256 is pinned. `gradle/verification-metadata.xml` pins SHA-256 for every dependency and plugin. Google's repo is restricted to Google groups. |

## Build

```bash
export JAVA_HOME="/c/Program Files/Android/Android Studio/jbr"   # PowerShell: $env:JAVA_HOME = '...'
./gradlew testDebugUnitTest      # protocol tests vs ../docs/test-vectors.json
./gradlew assembleDebug          # app/build/outputs/apk/debug/app-debug.apk (includes the test hook)
./gradlew assembleRelease        # app/build/outputs/apk/release/app-release.apk (R8, signed)
```

If you change dependencies, refresh the checksum pins:
`./gradlew --write-verification-metadata sha256 assembleDebug assembleRelease testDebugUnitTest lintDebug`
(then re-add the `<trusted-artifacts>` block for `-sources`/`-javadoc` jars).

## Debug-build test hook (not in release)

`src/debug/` adds an exported `DebugHookActivity` for automated end-to-end tests.
The release APK does not contain it; check with
`aapt2 dump xmltree --file AndroidManifest.xml app-release.apk | grep DebugHook`.
Quote exactly as shown, because `&` must be protected from the device shell. From
Git Bash, also `export MSYS_NO_PATHCONV=1`.

```bash
# Pair without a camera (runs the normal pairing flow + UI):
adb shell "am start -n io.c2rd.dropper/app.dropper.debug.DebugHookActivity --es pair_uri 'dropper://pair?v=1&a=10.0.2.2:47823&k=...&s=...&n=PC'"
# Queue a file of N random bytes (logs id + sha256 to tag DropperDebug):
adb shell "am start -n io.c2rd.dropper/app.dropper.debug.DebugHookActivity --ei send_random 5000000"
# Queue a text item (logs id + sha256 of the UTF-8 bytes):
adb shell "am start -n io.c2rd.dropper/app.dropper.debug.DebugHookActivity --es send_text 'hello from the phone'"
# Dump connection state + last 20 activity rows (texts are logged as length + sha256):
adb shell "am start -n io.c2rd.dropper/app.dropper.debug.DebugHookActivity --ez dump true"; adb logcat -d -s DropperDebug
# Verify received files:
adb shell "ls -l /sdcard/Download/Dropper/ && sha256sum /sdcard/Download/Dropper/*"
```

The emulator reaches the host's loopback at `10.0.2.2`, which counts as an
RFC 1918 address and so is allowed.

## Source map

```
app/src/main/java/app/dropper/
  proto/      pure-JVM protocol: Crypto (HKDF/HMAC/SAS/proof), Packets (preamble, discovery,
              IPv4 rules), Frames (reader/writer), Messages (JSON + validation, name sanitizing,
              link detection), PairingUri (QR parsing)
  security/   Identity (Keystore key + client KeyManager), Tls (pinning TrustManager, TLS 1.3
              client), SecureStore (Keystore AES-GCM files)
  data/       Models, Repositories (pairing, settings, history, progress), Outbox
  net/        Lan (network monitor, bound sockets, discovery), Session (full-duplex transfer
              engine + keepalive), Sinks (MediaStore/text), ConnectionManager (reconnect,
              backoff, discovery fallback), PairingController
  service/    ConnectionService (connectedDevice FGS), BootReceiver, ActionReceiver, Notifications
  ui/         MainActivity, PairingScreen, HomeScreen, SettingsScreen, ShareActivity, Theme, Format
app/src/debug/  DebugHookActivity (test hook, debug builds only)
app/src/test/   JVM unit tests (vectors, frames, messages, QR, names)
```
