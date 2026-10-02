#include "endpoint_internal.h"
#include <string.h>

bool nm_esp_endpoint_supported(const char *type)
{
    return type && (!strcmp(type, "icmp") || !strcmp(type, "dns") || !strcmp(type, "rawconnect") ||
                    !strcmp(type, "http") || !strcmp(type, "httphtml") || !strcmp(type, "https") ||
                    !strcmp(type, "blebroadcast") || !strcmp(type, "blebroadcastlisten") ||
                    !strcmp(type, "quantum") || !strcmp(type, "quantumcert") ||
                    !strcmp(type, "nmap"));
}

nm_esp_result nm_esp_endpoint_run(const nm_monitor_record *monitor)
{
    const char *address = monitor ? monitor->Address : NULL;
    const char *type = monitor ? monitor->EndPointType : NULL;
    nm_esp_result invalid =
        nm_endpoint_result(type, NM_ENDPOINT_EXCEPTION, 0, 0, "Invalid monitor");
    if (!nm_esp_endpoint_supported(type) ||
        (strcmp(type, "blebroadcastlisten") && (!address || !*address || strlen(address) > 1024)))
        return invalid;
    if (monitor->Timeout < 0)
        return invalid;
    unsigned timeout = (unsigned)monitor->Timeout, port = monitor->Port;
    if (timeout == 0)
        timeout = 10000;
    if (timeout > 600000)
        timeout = 600000;
    if (!strcmp(type, "icmp"))
        return nm_endpoint_check_icmp(address, timeout);
    if (!strcmp(type, "dns"))
        return nm_endpoint_check_dns(address, timeout);
    if (!strcmp(type, "rawconnect"))
        return nm_endpoint_check_tcp(address, port, timeout);
    if (!strcmp(type, "nmap"))
        return nm_endpoint_check_nmap(address, port, timeout);
    if (!strcmp(type, "quantum") || !strcmp(type, "quantumcert"))
        return nm_endpoint_check_quantum(address, type, port, timeout);
    if (!strcmp(type, "blebroadcast") || !strcmp(type, "blebroadcastlisten"))
        return nm_endpoint_check_ble(monitor, timeout);
    return nm_endpoint_check_http(address, type, port, timeout);
}
