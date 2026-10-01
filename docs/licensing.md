# Licensing and firmware releases

Copyright (c) 2026 Mahadeva. Project-authored source and documentation in this
repository are licensed under GPL-3.0-only; the complete license text is in
[`LICENSE`](../LICENSE). This change applies to this version of the project.
Previously published MIT-licensed versions remain available under their
original license; changing the current license does not revoke those grants.

Third-party code is not relicensed by the root `LICENSE`:

| Component | License and where to find it |
| --- | --- |
| wolfSSL/wolfCrypt | GPLv3 for the open-source build; see `third_party/wolfssl/LICENSING` and `COPYING` after initializing the submodule. Its special GPLv2 exception does not cover this processor. |
| yyjson | MIT; see `third_party/yyjson/LICENSE` after initializing the submodule. |
| Brotli | MIT; see its `LICENSE` in the resolved `espressif/brotli` component. Preserve notices in the quality-zero specialization. |
| ESP-MQTT | Apache-2.0; see its `LICENSE` in the resolved `espressif/mqtt` component. |
| ESP-IDF and its other components | Their upstream notices and licenses apply separately; inspect the exact resolved build inputs for each release. |

The quantum firmware links wolfSSL into the application. A binary release
cannot be labelled “MIT-only”; it is distributed under GPLv3 with the
applicable third-party notices. Keeping dependency sources in submodules or
the ESP-IDF component registry does not remove the obligation to make the
complete corresponding source available to recipients.

Before publishing a factory or OTA image:

1. Publish the matching project commit and corresponding-source archive.
   `tools/package_corresponding_source.py` packages the project, exact Git
   submodules, checksum-verified Brotli and ESP-MQTT sources, build config,
   scripts, dependency lock, notices and SBOM. ESP-IDF is pinned to the exact
   upstream commit recorded in the archive manifest and fetched from that
   immutable revision. A GitHub-generated source archive alone omits Git
   submodule contents; do not present it as the complete source package.
2. Include GPLv3 and the applicable third-party copyright/license notices
   with the release. Link each binary to its matching source package and give
   recipients the rights required by those licenses. A link to a moving branch
   or to an unrelated newer source revision is not sufficient.
3. Do not include Wi-Fi credentials, OAuth tokens, enrolled flash, or the
   operator's private OTA signing key in a public source package. This build
   enables signed application images but does not enable hardware Secure Boot
   or flash encryption. The documented ROM factory-flash procedure replaces
   the bootloader and application; a user can build a factory image with a
   signing key they control and install it over USB. The official OTA key is
   not needed for that route, which erases existing device configuration.
   Recheck this installation information if hardware Secure Boot, flash
   encryption or a locked ROM-download policy is enabled in a future build.
4. Test the source package by building from a clean checkout with its
   dependencies, then run the normal firmware and hardware checks.

The v0.3.0 source package is stored in
`release-source/NetworkMonitorProcessorAgentEmbedded-v0.3.0-source.tar.gz`.
Attach it and the matching `THIRD_PARTY_NOTICES.md`, SBOM and checksum file to
the same GitHub release as the factory image. It is also committed here so
recipients can obtain it independently of GitHub's generated source archives.
