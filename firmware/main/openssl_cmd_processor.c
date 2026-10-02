#include "openssl_cmd_processor.h"
#include "openssl_runner.h"
#include "cmd_output.h"
#include "nm_memory.h"
#include <string.h>

const char *nm_openssl_cmd_help(void)
{
    return "Embedded OpenSSL-compatible TLS diagnostics implemented by wolfSSL.\n"
           "Usage: s_client -connect host:port [-servername host] [-groups group:group] [-tls1_3] "
           "[-showcerts] [-brief] [-verify_return_error]\n"
           "Also: version; list -tls-groups. Optional leading openssl is accepted.\n"
           "TLS 1.3 only. Output is a typed TLS/certificate summary, not PEM or byte-for-byte "
           "OpenSSL output.\n"
           "Default s_client observes certificates without requiring trust, like OpenSSL; "
           "-verify_return_error requires trusted TLS.\n"
           "No shell, pipelines, x509/file inputs, key generation, cipher overrides or TLS 1.2. "
           "Unsupported arguments fail explicitly.\n";
}
static bool valid_host(const char *host)
{
    if (!*host || strlen(host) > 253)
        return false;
    for (; *host; ++host)
        if (*host <= ' ' || *host == '/' || *host == '@' || *host == '?' || *host == '#')
            return false;
    return true;
}
bool nm_openssl_cmd_parse(const char *arguments, nm_openssl_command *request, const char **error)
{
    if (!request || !error)
        return false;
    *request = (nm_openssl_command){.timeout_ms = 59000};
    *error =
        "Invalid or unsupported embedded OpenSSL arguments; request help for the supported subset";
    if (!arguments || strlen(arguments) > 4096)
        return false;
    const char *cursor = arguments;
    char item[512];
    if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
        return false;
    if (!strcmp(item, "openssl") && !nm_cmd_argument_token(&cursor, item, sizeof(item)))
        return false;
    if (!strcmp(item, "version") || !strcmp(item, "list")) {
        request->operation = !strcmp(item, "version") ? NM_OPENSSL_VERSION : NM_OPENSSL_GROUPS;
        if (request->operation == NM_OPENSSL_GROUPS &&
            (!nm_cmd_argument_token(&cursor, item, sizeof(item)) || strcmp(item, "-tls-groups")))
            return false;
        if (!nm_cmd_argument_token(&cursor, item, sizeof(item)) || *item)
            return false;
        *error = NULL;
        return true;
    }
    if (strcmp(item, "s_client"))
        return false;
    while (*cursor) {
        if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
            return false;
        if (!*item)
            break;
        if (!strcmp(item, "-showcerts") || !strcmp(item, "-brief") || !strcmp(item, "-tls1_3"))
            continue;
        if (!strcmp(item, "-verify_return_error")) {
            request->verify = true;
            continue;
        }
        bool connection = !strcmp(item, "-connect"), name = !strcmp(item, "-servername");
        bool groups = !strcmp(item, "-groups") || !strcmp(item, "-curves");
        if ((!connection && !name && !groups) ||
            !nm_cmd_argument_token(&cursor, item, sizeof(item)) || !*item)
            return false;
        if (connection) {
            if (request->host[0])
                return false;
            char *port = strrchr(item, ':');
            if (!port || !nm_cmd_argument_number(port + 1, 65535, &request->port))
                return false;
            *port = 0;
            char *host = item;
            size_t length = strlen(host);
            if (length >= 2 && *host == '[' && host[length - 1] == ']') {
                host[length - 1] = 0;
                ++host;
            }
            if (!valid_host(host))
                return false;
            memcpy(request->host, host, strlen(host) + 1);
        } else if (name) {
            if (request->servername[0] || !valid_host(item))
                return false;
            memcpy(request->servername, item, strlen(item) + 1);
        } else {
            if (request->groups[0])
                return false;
            memcpy(request->groups, item, strlen(item) + 1);
        }
    }
    if (!request->host[0])
        return false;
    *error = NULL;
    return true;
}
nm_cmd_result nm_openssl_cmd_run(const nm_openssl_command *request, const atomic_bool *cancellation)
{
    nm_cmd_output output;
    nm_cmd_output_init(&output, 8192);
    if (cancellation && atomic_load(cancellation)) {
        nm_cmd_output_append(&output, "OpenSSL command canceled or timed out.\n");
        return nm_cmd_output_finish(&output, false);
    }
    if (request->operation == NM_OPENSSL_VERSION) {
        nm_cmd_output_append(&output,
                             "Embedded OpenSSL-compatible adapter; provider=wolfSSL; TLS=1.3\n");
        return nm_cmd_output_finish(&output, true);
    }
    if (request->operation == NM_OPENSSL_GROUPS) {
        for (size_t i = 0; i < nm_openssl_group_count(); ++i)
            nm_cmd_output_append(&output, "%s\n", nm_openssl_group_at(i));
        return nm_cmd_output_finish(&output, true);
    }
    nm_openssl_request connection = {
        .host = request->servername[0] ? request->servername : request->host,
        .connect_host = request->host,
        .port = request->port,
        .timeout_ms = request->timeout_ms,
        .group = request->groups[0] ? request->groups
                                    : "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:"
                                      "MLKEM512:MLKEM768:MLKEM1024:X25519:secp256r1",
        .show_certificates = !request->verify,
        .cancellation = cancellation};
    nm_tls_inspection result = nm_openssl_execute(&connection);
    bool success = result.observation.outcome == NM_QUANTUM_OK ||
                   result.observation.outcome == NM_QUANTUM_NEGATIVE;
    if (result.observation.outcome == NM_QUANTUM_CANCELLED ||
        result.observation.outcome == NM_QUANTUM_TIMEOUT)
        nm_cmd_output_append(&output, "OpenSSL command canceled or timed out.\n");
    else {
        nm_cmd_output_append(&output, "Protocol: %s\nCipher: %s\nNegotiated TLS group: %s\n",
                             result.observation.protocol[0] ? result.observation.protocol : "none",
                             result.observation.cipher[0] ? result.observation.cipher : "none",
                             result.observation.group[0] ? result.observation.group : "none");
        if (result.observation.summary)
            nm_cmd_output_append(&output, "%s\n", result.observation.summary);
        if (!success)
            nm_cmd_output_append(&output, "TLS connection failed: %s\n",
                                 result.observation.error_message[0]
                                     ? result.observation.error_message
                                     : "connection or local resource error");
    }
    if (cancellation && atomic_load(cancellation))
        success = false;
    nm_tls_inspection_release(&result);
    return nm_cmd_output_finish(&output, success);
}
