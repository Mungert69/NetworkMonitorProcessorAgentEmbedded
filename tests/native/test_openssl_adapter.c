#include "openssl_cmd_processor.h"
#include "openssl_runner.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned inspections;
static nm_quantum_outcome outcome = NM_QUANTUM_NEGATIVE;
static bool trusted = true;
static nm_openssl_command expected;
nm_tls_inspection nm_tls_inspect(const nm_tls_inspection_request *r)
{
    ++inspections;
    assert(r->diagnostics && r->diagnostics->certificate_details);
    assert(!strcmp(r->connect_host, expected.host));
    assert(!strcmp(r->host, expected.servername[0] ? expected.servername : expected.host));
    assert(r->port == expected.port && r->timeout_ms == expected.timeout_ms);
    assert(r->mode == (expected.verify ? NM_TLS_INSPECT_HANDSHAKE : NM_TLS_INSPECT_CERTIFICATE));
    assert(r->diagnostics->no_sni == expected.no_sni);
    assert(r->diagnostics->explicit_sni == (expected.servername[0] != 0));
    assert(r->diagnostics->export_chain == expected.show_certificates);
    assert(r->diagnostics->address_family == (int)expected.address_family);
    assert(r->diagnostics->tls_version == expected.tls_version);
    assert(!strcmp(r->diagnostics->alpn ? r->diagnostics->alpn : "", expected.alpn));
    assert(!strcmp(r->diagnostics->ciphersuites ? r->diagnostics->ciphersuites : "",
                   expected.ciphersuites[0]     ? expected.ciphersuites
                   : expected.tls_version == 12 ? nm_openssl_tls12_ciphers()
                                                : ""));
    assert(!strcmp(r->diagnostics->verify_host ? r->diagnostics->verify_host : "",
                   expected.verify_host));
    nm_tls_inspection result = {.observation = {.outcome = outcome, .certificate_trusted = trusted}};
    strcpy(result.observation.protocol, "TLSv1.3");
    strcpy(result.observation.cipher, "TLS_AES_128_GCM_SHA256");
    strcpy(result.observation.alpn, "h2");
    result.observation.summary = malloc(80);
    assert(result.observation.summary);
    strcpy(result.observation.summary, trusted ? "Certificate PQC: no"
                                              : "Certificate PQC: no; Certificate trust: not trusted");
    if (r->diagnostics->export_chain) {
        result.observation.certificate_pem = malloc(80);
        assert(result.observation.certificate_pem);
        strcpy(result.observation.certificate_pem,
               "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n");
    }
    return result;
}
void nm_tls_inspection_release(nm_tls_inspection *r)
{
    free(r->observation.summary);
    free(r->observation.certificate_pem);
}
static bool parse(const char *text, nm_openssl_command *command)
{
    const char *error;
    bool ok = nm_openssl_cmd_parse(text, command, &error);
    assert(ok ? error == NULL : error != NULL);
    return ok;
}
int main(void)
{
    const char *valid[] = {
        "openssl version -a",
        "list -tls-groups",
        "ciphers",
        "ciphers -s -tls1_3",
        "help",
        "s_client -help",
        "s_client example.com",
        "s_client -connect example.com:443",
        "s_client -host example.com -port 8443",
        "s_client -port 8443 -host example.com",
        "s_client -connect [::1]:8443 -6 -servername example.com -showcerts",
        "s_client -connect 127.0.0.1 -noservername -4 -verify_ip 127.0.0.1",
        "s_client -connect example.com -verify_hostname other.example -verify_return_error",
        "s_client -connect example.com -groups X25519 -brief -no_tls1_2",
        "s_client -connect example.com -min_protocol TLSv1.3 -max_protocol TLSv1.3",
        "s_client -connect example.com -alpn h2,http/1.1 -ciphersuites TLS_AES_128_GCM_SHA256",
        "s_client -connect example.com -showcerts -verify_return_error",
        "s_client -connect example.com -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256",
        "s_client -connect example.com -cipher ECDHE-ECDSA-AES256-GCM-SHA384 -tls1_2",
        "ciphers -s -tls1_2",
        "s_client -connect example.com   ",
        "ciphers -s   ",
        "s_client -connect example.com -no_tls1_3 -no-interactive -nocommands",
        "list -tls1_3 -tls-groups",
        "list -tls-groups -tls1_2"};
    nm_openssl_command command;
    for (size_t i = 0; i < sizeof(valid) / sizeof(*valid); ++i) {
        assert(parse(valid[i], &command));
        expected = command;
        nm_cmd_result result = nm_openssl_cmd_run(&command, NULL);
        assert(result.success && result.output);
        if (command.operation == NM_OPENSSL_CLIENT) {
            assert(strstr(result.output, "ALPN protocol: h2"));
            assert(!!strstr(result.output, "BEGIN CERTIFICATE") == command.show_certificates);
            assert(!!strstr(result.output, "Certificate PQC") == !command.brief);
        }
        if (command.operation == NM_OPENSSL_GROUPS)
            assert(!!strstr(result.output, "MLKEM768") == (command.tls_version != 12));
        free(result.output);
    }
    const char *invalid[] = {"",
                             "x509 -in cert.pem",
                             "s_client",
                             "s_client -tls1_1 -connect host",
                             "s_client -connect host -cipher AES256-SHA",
                             "s_client -connect host -CAfile file",
                             "s_client -connect host -starttls smtp",
                             "s_client -connect host | x509",
                             "s_client -connect host;evil",
                             "s_client -connect host '' -showcerts",
                             "s_client -connect host -alpn h2,",
                             "s_client -connect host -alpn ,h2",
                             "s_client -connect host -alpn 'h2, http/1.1'",
                             "s_client -connect host -4 -6",
                             "s_client -connect host -noservername -servername name",
                             "s_client -connect host -servername name -noservername",
                             "s_client -connect host -verify_ip not-an-ip",
                             "s_client -connect host -verify_hostname a -verify_ip 127.0.0.1",
                             "s_client -connect host:0",
                             "s_client -connect host:65536",
                             "s_client -connect ::1",
                             "s_client -connect [host]:443",
                             "s_client -connect host -connect host",
                             "s_client -host host -host host",
                             "s_client -connect host -port 443",
                             "s_client -connect host -ciphersuites ALL",
                             "s_client -connect host -ciphersuites TLS_AES_128_GCM_SHA256:unknown",
                             "s_client -connect host -ciphersuites TLS_AES_128_GCM_SHA256:",
                             "s_client -connect host -min_protocol TLSv1.2",
                             "version -bogus",
                             "list",
                             "ciphers -v",
                             "s_client -connect host -tls1_2 -tls1_3",
                             "s_client -connect host -tls1_2 -ciphersuites TLS_AES_128_GCM_SHA256",
                             "s_client -connect host -cipher ECDHE-RSA-AES128-GCM-SHA256",
                             "s_client -connect host -tls1_2 -min_protocol TLSv1.3",
                             "s_client -connect host -min_protocol TLSv1.3 -tls1_2",
                             "ciphers -tls1_2 -tls1_3",
                             "s_client -connect host -no_tls1_3 -no_tls1_2",
                             "list -tls1_2 -tls1_3 -tls-groups"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i)
        assert(!parse(invalid[i], &command));
    char oversized[4098];
    memset(oversized, 'a', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = 0;
    assert(!parse(oversized, &command));
    assert(parse("s_client -connect example.com -showcerts", &command));
    trusted = false;
    for (unsigned brief = 0; brief < 2; ++brief) {
        command.brief = brief != 0;
        expected = command;
        nm_cmd_result report = nm_openssl_cmd_run(&command, NULL);
        const char *note = strstr(report.output, "Certificate trust: not trusted");
        assert(report.success && note);
        assert(!strstr(note + 1, "Certificate trust:"));
        free(report.output);
    }
    command.brief = false;
    expected = command;
    outcome = NM_QUANTUM_LOCAL_FAILURE;
    nm_cmd_result result = nm_openssl_cmd_run(&command, NULL);
    assert(!result.success && strstr(result.output, "TLS connection failed"));
    assert(strstr(result.output, "Certificate trust: verification incomplete"));
    free(result.output);
    unsigned before = inspections;
    atomic_bool canceled = true;
    result = nm_openssl_cmd_run(&command, &canceled);
    assert(!result.success && inspections == before);
    free(result.output);
    nm_tls_diagnostic_options bad = {.ciphersuites = "ALL"};
    nm_openssl_request r = {.host = "example.com", .diagnostics = &bad};
    assert(nm_openssl_execute(&r).observation.outcome == NM_QUANTUM_ERROR);
    r.diagnostics = NULL;
    r.group = "X25519:unknown";
    assert(nm_openssl_execute(&r).observation.outcome == NM_QUANTUM_ERROR);
    assert(inspections == before);
    assert(!strcmp(nm_openssl_group_name("prime256v1"), "secp256r1"));
    assert(!strcmp(nm_openssl_group_name("P-384"), "secp384r1"));
    assert(!strcmp(nm_openssl_cipher_name("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                   "ECDHE-RSA-AES128-GCM-SHA256"));
    assert(parse("s_client -connect example.com", &command) && command.port == 4433);
    puts("OpenSSL parser/policy/runner tests passed");
    return 0;
}
