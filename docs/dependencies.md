# Dependency update policy

Keep ESP-IDF and its managed components pinned. `firmware/idf_component.yml`
selects the Brotli and MQTT component versions; `firmware/dependencies.lock`
records the resolved packages and integrity hashes. `third_party/yyjson` is a
Git submodule pinned by the parent commit. Pins make builds reproducible, not
automatically secure: review upstream releases and advisories regularly.

The quantum feature branch also pins wolfSSL in `third_party/wolfssl` as a Git
submodule. Review its upstream security updates before changing that pin, and
run the quantum native, firmware and board tests. Its open-source license is
GPLv3; see [licensing and release requirements](licensing.md). A firmware
release must identify an immutable project tag, pinned submodule commits,
managed-component lockfile and upstream ESP-IDF revision. A GitHub-generated
source snapshot alone omits submodule contents; use a recursive clone for the
complete project checkout.

The weekly scheduled check compares yyjson's pinned release and Brotli/MQTT's
exact manifest pins against their latest stable upstream releases. It opens one
tracking issue when review is needed; it does not silently change a firmware
dependency. Dependabot proposes GitHub Actions updates weekly. A git-submodule
Dependabot updater is deliberately not used here because its tracking target
need not be a reviewed yyjson release tag. Repository vulnerability alerts
and automated security updates are enabled. Review ESP-IDF itself at least
monthly and promptly after a relevant advisory; the registry checker does not
track the toolchain.

For a managed component upgrade, change its version in
`firmware/main/idf_component.yml`, then use the pinned IDF toolchain to run
`idf.py update-dependencies` and commit the regenerated lockfile. Do not hand
edit hashes. For yyjson, update the submodule to a reviewed upstream release.
Review release notes and code paths before accepting automated pull requests.

Every upgrade needs host tests, a complete firmware build, and the relevant
integration tests. MQTT upgrades additionally need a device/emulator broker
connection test with an OAuth-sized password, command reception, and result
publication. OTA release still requires testing on the target device. Never
place the permanent OTA signing private key in GitHub Actions or a public
repository.

Brotli has an additional constraint: the firmware uses a reviewed quality-zero
encoder specialization. `tools/specialize_brotli.py` checks the exact upstream
`encode.c` hash and deliberately stops the build if that source changes. A
Brotli update must review this specialization and the actual encoder source
closure, then run the sanitizer-backed quality-zero parity tests described in
[`brotli-quality-zero.md`](brotli-quality-zero.md). The decoder and wire format
must remain compatible with .NET. Never bypass the source hash to make an
upgrade pass.
