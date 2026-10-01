/* Current backend catalog: keep aligned with EndPointTypeFactory and
 * CmdProcessorProvider. Unknown/dynamic commands are never executed locally. */
#ifndef NM_CAPABILITY_DEFAULTS_H
#define NM_CAPABILITY_DEFAULTS_H
#if defined(CONFIG_BT_NIMBLE_ENABLED) && CONFIG_BT_NIMBLE_ENABLED
#define NM_DISABLED_ENDPOINTS_JSON "[\"httpfull\",\"sitehash\",\"configintegrity\",\"smtp\",\"nmap\",\"nmapvuln\",\"crawlsite\",\"dailycrawl\",\"dailyhugkeepalive\",\"hugwake\"]"
#else
#define NM_DISABLED_ENDPOINTS_JSON "[\"httpfull\",\"sitehash\",\"configintegrity\",\"smtp\",\"blebroadcast\",\"blebroadcastlisten\",\"nmap\",\"nmapvuln\",\"crawlsite\",\"dailycrawl\",\"dailyhugkeepalive\",\"hugwake\"]"
#endif
#define NM_DISABLED_COMMANDS_JSON "[\"nmap\",\"meta\",\"metalive\",\"openssl\",\"busybox\",\"searchweb\",\"searchengage\",\"crawlpage\",\"crawlsite\",\"hugspacewake\",\"hugspacekeepalive\",\"ping\",\"quantumconnect\",\"quantumportscanner\",\"quantuminfo\",\"quantumcert\",\"blebroadcast\",\"blebroadcastlisten\",\"cameracapture\",\"msfconsole\",\"quantum-cert\"]"
#endif
