# Publishing Dropper

## Cutting a GitHub release

1. **Bump the versions.** Keep them identical.
   - `android/app/build.gradle.kts`: `versionCode` (+1) and `versionName`
   - `pc/Directory.Build.props`: `<Version>`
   - `pc/Dropper.Core/Protocol/Wire.cs`: `AppVersion`
2. **Test.**
   ```powershell
   dotnet test pc\Dropper.Tests
   cd android; .\gradlew testDebugUnitTest
   ```
3. **Build the release artifacts.**
   ```powershell
   dotnet publish pc\Dropper.App\Dropper.App.csproj -c Release -r win-x64 --self-contained false `
     -p:PublishSingleFile=true -p:DebugType=none -o out\win
   # zip out\win\Dropper.exe + pc\install.ps1 + pc\uninstall.ps1 -> Dropper-<v>-windows-x64.zip
   cd android; .\gradlew assembleRelease      # app\build\outputs\apk\release\app-release.apk
   ```
4. **Publish.** Tag `v<version>`, then attach the zip, the APK renamed to
   `Dropper-<v>.apk`, and a `SHA256SUMS.txt`:
   ```powershell
   gh release create v<version> Dropper-<v>-windows-x64.zip Dropper-<v>.apk SHA256SUMS.txt --title "Dropper <v>" --notes-file notes.md
   ```

**The signing key.** The APK is signed with the key in
`%USERPROFILE%\.dropper\signing`. Every later build has to use that same key, or
Android refuses to install it as an update. Back the folder up offline, and
never commit it.

## Google Play: what has to change first

The GitHub build is designed for sideloading. Play's policies reject parts of
it as-is, so plan a separate `play` build flavor.

| Item | Why | What to do |
|---|---|---|
| **App bundle** | Play takes `.aab`, not `.apk`. | `.\gradlew bundleRelease` |
| **Target SDK** | New apps and updates must target a recent API level, currently 36. The app targets 35. | Raise `targetSdk` to 36. The QR scanner screen relies on the API 35 edge-to-edge opt-out, so it first needs an inset-aware layout. |
| **`REQUEST_INSTALL_PACKAGES`** | A restricted permission. Play allows it only when installing packages is the app's core purpose, and a file-transfer app is likely to be refused. | Drop it from the `play` flavor. Received APKs then open through the chooser or the Files app instead of directly. |
| **`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`** | Also restricted, with few accepted use cases. | Remove it in `play`, and link to the battery settings page instead. |
| **Foreground service `connectedDevice`** | Needs a Play Console declaration explaining the use, plus a short demo video. | Describe it as "keeps a connection to the user's paired PC on the local network so transfers arrive instantly". |
| **Privacy policy + Data safety** | A privacy policy URL is required for every app. | Dropper collects nothing and sends nothing off the local network. State that, and answer "no data collected / shared" in the Data safety form. |
| **Play App Signing** | Google holds the app signing key. | Enroll in Play App Signing and use the existing `.dropper\signing` key as the **upload key**, or let Play generate one. Play-installed and GitHub-installed copies then carry different signatures and can't update each other. Tell users to pick one source. |
| **Listing** | The name "Dropper" may collide with existing listings or trademarks. | Search Play before submitting; consider "Dropper by C-Squared". |

The app ID `io.c2rd.dropper` is permanent once published. Don't change it again.
