# Third-party notices for firmware v0.4.1

This firmware is distributed under GPL-3.0-only for project-authored code.
The dependencies below keep their own terms; this file does not relicense them.
The repository tag identifies project source and pinned Git submodules; the
dependency lock and this notice identify the managed component sources.

| Component | Exact release / source revision | License |
|---|---|---|
| wolfSSL / wolfCrypt | 5.9.2-stable, `ac01707f552c611fbd135cc723b2682b3e7f80f2` | GPL-3.0; see `third_party/wolfssl/COPYING` and `LICENSING` |
| yyjson | 0.13.0, `6447536015f3d600f3d65323b10976103b337ca7` | MIT; see `third_party/yyjson/LICENSE` |
| Google Brotli | ESP Component `espressif/brotli` 1.2.0, upstream commit `04722cb30b12a4da491aadc1e7036e57960e7ff9` | MIT; see `third_party/espressif__brotli/LICENSE` and `brotli/brotli/LICENSE` |
| ESP-MQTT | `espressif/mqtt` 1.1.0, upstream commit `1a1e5788a5cf57a0f44a3c6c061407f6c9be1026` | Apache-2.0; see `third_party/espressif__mqtt/LICENSE` |
| ESP-IDF | v6.1, source commit `fff9895c82d744c7237be8847347bdd1b07c6643` | Apache-2.0 plus component-specific terms; see the IDF `LICENSE` and each component's notices |

The IDF build's CycloneDX SBOM is included as
`NetworkMonitorProcessorAgentEmbedded-v0.4.1.cdx.json`. ESP-IDF and its
components also include BSD, MIT, ISC, and other separately licensed works;
consult the SBOM and the corresponding files in the pinned ESP-IDF source tree.
The IDF source is available at
<https://github.com/espressif/esp-idf/tree/fff9895c82d744c7237be8847347bdd1b07c6643>.

For project sources, check out the release tag with
`git clone --recurse-submodules`; the submodule commits are pinned by the
tagged repository. Brotli and ESP-MQTT source versions and integrity hashes
are pinned in `firmware/dependencies.lock` and can be fetched by ESP-IDF's
component manager. The private OTA signing key and provisioned device data
are intentionally not included. See `docs/licensing.md` for release and
installation information.
