#include "openssl_cmd_processor.h"
#include "openssl_runner.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>

static bool valid_host(const char *host)
{
    if (!*host || strlen(host) > 253)
        return false;
    for (; *host; ++host)
        if (!isalnum((unsigned char)*host) && *host != '.' && *host != '-' && *host != ':' &&
            *host != '_')
            return false;
    return true;
}
static bool alpn_valid(const char *list)
{
    size_t length = 0;
    for (const unsigned char *p = (const unsigned char *)list;; ++p) {
        if (!*p || *p == ',') {
            if (!length || length > 255)
                return false;
            if (!*p)
                return true;
            length = 0;
        } else {
            if (*p <= ' ' || *p >= 127 || *p == ';' || *p == '|')
                return false;
            ++length;
        }
    }
}
static bool parse_connection(char *item, nm_openssl_command *request)
{
    if (request->host[0])
        return false;
    char *host = item, *port = NULL;
    if (*host == '[') {
        char *end = strchr(host, ']');
        if (!end || (end[1] && end[1] != ':'))
            return false;
        if (end[1])
            port = end + 2;
        *end = 0;
        ++host;
        unsigned char address[16];
        if (inet_pton(AF_INET6, host, address) != 1)
            return false;
    } else {
        port = strchr(host, ':');
        if (port) {
            *port++ = 0;
            if (strchr(port, ':'))
                return false;
        }
    }
    if (!valid_host(host) || (port && !nm_cmd_argument_number(port, 65535, &request->port)))
        return false;
    memcpy(request->host, host, strlen(host) + 1);
    return true;
}
bool nm_openssl_cmd_parse(const char *arguments, nm_openssl_command *request, const char **error)
{
    if (!request || !error)
        return false;
    *request = (nm_openssl_command){.timeout_ms = 59000, .port = 4433, .tls_version = 13};
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
    if (!strcmp(item, "help") || !strcmp(item, "-help")) {
        request->operation = NM_OPENSSL_HELP;
        if (!nm_cmd_argument_token(&cursor, item, sizeof(item)) || *item)
            return false;
        *error = NULL;
        return true;
    }
    if (!strcmp(item, "ciphers")) {
        request->operation = NM_OPENSSL_CIPHERS;
        bool version_seen = false;
        while (*cursor) {
            while (isspace((unsigned char)*cursor))
                ++cursor;
            if (!*cursor)
                break;
            if (!nm_cmd_argument_token(&cursor, item, sizeof(item)) ||
                (strcmp(item, "-s") && strcmp(item, "-tls1_3") && strcmp(item, "-tls1_2")))
                return false;
            if (strcmp(item, "-s")) {
                unsigned version = !strcmp(item, "-tls1_2") ? 12 : 13;
                if (version_seen && request->tls_version != version)
                    return false;
                request->tls_version = version;
                version_seen = true;
            }
        }
        *error = NULL;
        return true;
    }
    if (!strcmp(item, "list")) {
        request->operation = NM_OPENSSL_GROUPS;
        bool selection = false, version_seen = false;
        while (*cursor) {
            while (isspace((unsigned char)*cursor))
                ++cursor;
            if (!*cursor)
                break;
            if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
                return false;
            if (!strcmp(item, "-tls-groups") && !selection)
                selection = true;
            else if (!strcmp(item, "-tls1_2") || !strcmp(item, "-tls1_3")) {
                unsigned version = !strcmp(item, "-tls1_2") ? 12 : 13;
                if (version_seen && request->tls_version != version)
                    return false;
                request->tls_version = version;
                version_seen = true;
            } else
                return false;
        }
        if (!selection)
            return false;
        *error = NULL;
        return true;
    }
    if (!strcmp(item, "version")) {
        request->operation = NM_OPENSSL_VERSION;
        if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
            return false;
        if (*item &&
            (strcmp(item, "-a") || !nm_cmd_argument_token(&cursor, item, sizeof(item)) || *item))
            return false;
        *error = NULL;
        return true;
    }
    if (strcmp(item, "s_client"))
        return false;
    bool port_set = false, connection_set = false, version_set = false;
    bool cipher12 = false, cipher13 = false, protocol_bound = false;
    while (*cursor) {
        while (isspace((unsigned char)*cursor))
            ++cursor;
        if (!*cursor)
            break;
        if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
            return false;
        if (!*item)
            return false;
        if (!strcmp(item, "-showcerts")) {
            request->show_certificates = true;
            continue;
        }
        if (!strcmp(item, "-brief")) {
            request->brief = true;
            continue;
        }
        if (!strcmp(item, "-tls1_3") || !strcmp(item, "-tls1_2") || !strcmp(item, "-no_tls1_2") ||
            !strcmp(item, "-no_tls1_3")) {
            unsigned version = !strcmp(item, "-tls1_2") || !strcmp(item, "-no_tls1_3") ? 12 : 13;
            if ((version_set && request->tls_version != version) ||
                (protocol_bound && version != 13))
                return false;
            request->tls_version = version;
            version_set = true;
            continue;
        }
        if (!strcmp(item, "-noservername")) {
            if (request->servername[0] || request->no_sni)
                return false;
            request->no_sni = true;
            continue;
        }
        if (!strcmp(item, "-no-interactive") || !strcmp(item, "-nocommands"))
            continue; /* This adapter never has an interactive stdin session. */
        if (!strcmp(item, "-4") || !strcmp(item, "-6")) {
            if (request->address_family)
                return false;
            request->address_family = item[1] == '4' ? 4 : 6;
            continue;
        }
        if (!strcmp(item, "-help") && !request->host[0]) {
            request->operation = NM_OPENSSL_HELP;
            if (!nm_cmd_argument_token(&cursor, item, sizeof(item)) || *item)
                return false;
            *error = NULL;
            return true;
        }
        if (item[0] != '-') {
            if (port_set || !parse_connection(item, request))
                return false;
            connection_set = true;
            continue;
        }
        if (!strcmp(item, "-verify_return_error")) {
            request->verify = true;
            continue;
        }
        bool connection = !strcmp(item, "-connect"), name = !strcmp(item, "-servername");
        bool groups = !strcmp(item, "-groups") || !strcmp(item, "-curves");
        bool host = !strcmp(item, "-host"), port = !strcmp(item, "-port");
        bool cipher = !strcmp(item, "-ciphersuites"), legacy_cipher = !strcmp(item, "-cipher");
        bool alpn = !strcmp(item, "-alpn");
        bool identity = !strcmp(item, "-verify_hostname"), ip = !strcmp(item, "-verify_ip");
        bool protocol = !strcmp(item, "-min_protocol") || !strcmp(item, "-max_protocol");
        if ((!connection && !name && !groups && !host && !port && !cipher && !legacy_cipher &&
             !alpn && !identity && !ip && !protocol) ||
            !nm_cmd_argument_token(&cursor, item, sizeof(item)) || !*item)
            return false;
        if (connection) {
            if (port_set || !parse_connection(item, request))
                return false;
            connection_set = true;
        } else if (host) {
            if (request->host[0] || !valid_host(item))
                return false;
            strcpy(request->host, item);
        } else if (port) {
            if (port_set || connection_set || !nm_cmd_argument_number(item, 65535, &request->port))
                return false;
            port_set = true;
        } else if (name) {
            if (request->no_sni || request->servername[0] || !valid_host(item))
                return false;
            memcpy(request->servername, item, strlen(item) + 1);
        } else if (groups) {
            if (request->groups[0])
                return false;
            memcpy(request->groups, item, strlen(item) + 1);
        } else if (cipher || legacy_cipher) {
            if (request->ciphersuites[0] || !(legacy_cipher ? nm_openssl_tls12_ciphers_valid(item)
                                                            : nm_openssl_ciphers_valid(item)))
                return false;
            strcpy(request->ciphersuites, item);
            cipher12 = legacy_cipher;
            cipher13 = cipher;
        } else if (alpn) {
            if (request->alpn[0] || !alpn_valid(item))
                return false;
            strcpy(request->alpn, item);
        } else if (identity || ip) {
            unsigned char address[16];
            if (request->verify_host[0] || !valid_host(item) ||
                (ip && inet_pton(AF_INET, item, address) != 1 &&
                 inet_pton(AF_INET6, item, address) != 1))
                return false;
            strcpy(request->verify_host, item);
            request->verify = true;
        } else {
            if (strcmp(item, "TLSv1.3") || request->tls_version != 13)
                return false;
            protocol_bound = true;
        }
    }
    if (!request->host[0] || (cipher12 && request->tls_version != 12) ||
        (cipher13 && request->tls_version != 13))
        return false;
    *error = NULL;
    return true;
}
