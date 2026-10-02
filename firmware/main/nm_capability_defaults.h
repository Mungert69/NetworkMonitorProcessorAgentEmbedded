/* Current backend catalog: keep aligned with EndPointTypeFactory and
 * CmdProcessorProvider. Unknown/dynamic commands are never executed locally. */
#ifndef NM_CAPABILITY_DEFAULTS_H
#define NM_CAPABILITY_DEFAULTS_H
#if defined(CONFIG_BT_NIMBLE_ENABLED) && CONFIG_BT_NIMBLE_ENABLED
#define NM_DISABLED_ENDPOINTS_JSON "[\"httpfull\",\"sitehash\",\"configintegrity\",\"smtp\",\"nmapvuln\",\"crawlsite\",\"dailycrawl\",\"dailyhugkeepalive\",\"hugwake\"]"
#else
#define NM_DISABLED_ENDPOINTS_JSON "[\"httpfull\",\"sitehash\",\"configintegrity\",\"smtp\",\"blebroadcast\",\"blebroadcastlisten\",\"nmapvuln\",\"crawlsite\",\"dailycrawl\",\"dailyhugkeepalive\",\"hugwake\"]"
#endif
#define NM_DISABLED_COMMANDS_JSON "[\"meta\",\"metalive\",\"busybox\",\"searchweb\",\"searchengage\",\"crawlpage\",\"crawlsite\",\"hugspacewake\",\"hugspacekeepalive\",\"ping\",\"blebroadcast\",\"blebroadcastlisten\",\"cameracapture\",\"msfconsole\"]"
#endif
