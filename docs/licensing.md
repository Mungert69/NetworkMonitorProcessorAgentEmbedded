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

1. Publish the matching project commit and complete source for the exact
   wolfSSL, yyjson, Brotli, ESP-MQTT and other covered build inputs, including
   local changes, configuration, dependency pins, and scripts needed to build
   and install the image. A GitHub-generated source archive alone omits Git
   submodule contents; do not present it as the complete source package.
2. Include GPLv3 and the applicable third-party copyright/license notices
   with the release. Link each binary to its matching source package and give
   recipients the rights required by those licenses. A link to a moving branch
   or to an unrelated newer source revision is not sufficient.
3. Do not include Wi-Fi credentials, OAuth tokens, enrolled flash, or the
   operator's private OTA signing key in a public source package. Signing an
   official image does not grant a right to withhold installation information
   required by GPLv3 section 6 where that section applies. Document the
   user-controlled ROM/factory flashing route for boards on which modified
   firmware can be installed without the operator's signing key; review any
   future Secure Boot or locked-bootloader policy before shipping devices.
4. Test the source package by building from a clean checkout with its
   dependencies, then run the normal firmware and hardware checks. Do not
   publish a wolfSSL-backed image before these release checks are complete.

The public factory images currently linked from the end-user setup guide are
separate releases. This document does not claim that an unpublished quantum
image has passed the release checks above.
