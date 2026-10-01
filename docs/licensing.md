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

1. Publish an immutable release tag for the exact source revision used to
   build the firmware. For a full source checkout, use
   `git clone --recurse-submodules` at that tag; this fetches the exact wolfSSL
   and yyjson commits recorded by the repository. The Brotli and ESP-MQTT
   component versions and integrity hashes are pinned in
   `firmware/dependencies.lock` and are fetched from Espressif's component
   registry by the documented ESP-IDF build. ESP-IDF itself is identified by
   the exact upstream commit in `THIRD_PARTY_NOTICES.md` and the SBOM. Do not
   present GitHub's auto-generated source snapshot as containing submodule
   contents.
2. Attach `THIRD_PARTY_NOTICES.md` and the matching CycloneDX SBOM to the
   release, and link users to the immutable source tag. Keep the license and
   dependency references tied to that firmware revision, not a moving branch.
3. Do not include Wi-Fi credentials, OAuth tokens, enrolled flash, or the
   operator's private OTA signing key in a public source package. This build
   enables signed application images but does not enable hardware Secure Boot
   or flash encryption. The documented ROM factory-flash procedure replaces
   the bootloader and application; a user can build a factory image with a
   signing key they control and install it over USB. The official OTA key is
   not needed for that route, which erases existing device configuration.
   Recheck this installation information if hardware Secure Boot, flash
   encryption or a locked ROM-download policy is enabled in a future build.
4. Test a clean recursive checkout at the release tag with the pinned
   dependencies, then run the normal firmware and hardware checks. The
   `tools/package_corresponding_source.py` utility can create a local source
   archive for recipients who specifically need one; generated archives are
   not committed or attached to releases to avoid duplicating source already
   available through the repository and upstream pinned dependencies.
