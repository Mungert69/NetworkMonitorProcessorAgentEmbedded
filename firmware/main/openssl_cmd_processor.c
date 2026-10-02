#include "openssl_cmd_processor.h"
#include "openssl_runner.h"
#include "cmd_output.h"
#include "nm_memory.h"
#include <string.h>

const char *nm_openssl_cmd_help(void)
{
    return "Embedded OpenSSL-compatible TLS diagnostics implemented by wolfSSL.\n"
           "Usage: s_client -connect host:port [-servername host] [-groups group:group] [-tls1_3] "
           "[-showcerts] [-brief] [-verify_return_error] [-noservername] [-4|-6]\n"
           "[-alpn h2,http/1.1] [-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384]\n"
           "TLS 1.2: -tls1_2 [-cipher ECDHE-RSA-AES128-GCM-SHA256] (AES-GCM only).\n"
           "[-verify_hostname host|-verify_ip address] [-min_protocol TLSv1.3] "
           "[-max_protocol TLSv1.3]\n"
           "Also: version [-a]; list -tls-groups [-tls1_2|-tls1_3]; "
           "ciphers [-s] [-tls1_2|-tls1_3]; help.\n"
           "Optional leading openssl, positional host[:port], or -host host -port port.\n"
           "TLS 1.3 default, or explicit TLS 1.2. Output is a typed summary, not byte-for-byte "
           "OpenSSL output.\n"
           "Default s_client observes certificates without requiring trust, like OpenSSL; "
           "-verify_return_error and identity checks require trusted TLS.\n"
           "-showcerts returns the presented PEM chain, not a verified chain.\n"
           "No shell, pipelines, x509/file inputs, key generation or cipher expressions. "
           "Unsupported arguments fail explicitly.\n";
}
nm_cmd_result nm_openssl_cmd_run(const nm_openssl_command *request, const atomic_bool *cancellation)
{
    nm_cmd_output output;
    if (!nm_cmd_output_init(&output, request && request->show_certificates ? 32768 : 8192))
        return nm_cmd_output_finish(&output, false);
    if (!request || (cancellation && atomic_load(cancellation))) {
        nm_cmd_output_append(&output, "OpenSSL command canceled or timed out.\n");
        return nm_cmd_output_finish(&output, false);
    }
    if (request->operation == NM_OPENSSL_HELP) {
        nm_cmd_output_append(&output, "%s", nm_openssl_cmd_help());
        return nm_cmd_output_finish(&output, true);
    }
    if (request->operation == NM_OPENSSL_CIPHERS) {
        nm_cmd_output_append(&output, "%s\n",
                             request->tls_version == 12 ? nm_openssl_tls12_ciphers()
                                                        : nm_openssl_ciphers());
        return nm_cmd_output_finish(&output, true);
    }
    if (request->operation == NM_OPENSSL_VERSION) {
        nm_cmd_output_append(
            &output, "Embedded OpenSSL-compatible adapter; provider=wolfSSL; TLS=1.2,1.3\n");
        return nm_cmd_output_finish(&output, true);
    }
    if (request->operation == NM_OPENSSL_GROUPS) {
        for (size_t i = 0; i < nm_openssl_group_count(); ++i)
            if (request->tls_version != 12 || !strstr(nm_openssl_group_at(i), "MLKEM"))
                nm_cmd_output_append(&output, "%s\n", nm_openssl_group_at(i));
        return nm_cmd_output_finish(&output, true);
    }
    if (request->operation != NM_OPENSSL_CLIENT) {
        nm_cmd_output_append(&output, "Unsupported OpenSSL operation\n");
        return nm_cmd_output_finish(&output, false);
    }
    nm_tls_diagnostic_options options = {
        .ciphersuites = request->ciphersuites[0]     ? request->ciphersuites
                        : request->tls_version == 12 ? nm_openssl_tls12_ciphers()
                                                     : NULL,
        .alpn = request->alpn[0] ? request->alpn : NULL,
        .verify_host = request->verify_host[0] ? request->verify_host : NULL,
        .no_sni = request->no_sni,
        .explicit_sni = request->servername[0] != 0,
        .certificate_details = true,
        .export_chain = request->show_certificates,
        .address_family = (int)request->address_family,
        .tls_version = request->tls_version};
    nm_openssl_request connection = {
        .host = request->servername[0] ? request->servername : request->host,
        .connect_host = request->host,
        .port = request->port,
        .timeout_ms = request->timeout_ms,
        .group = request->groups[0] ? request->groups
                 : request->tls_version == 12
                     ? "X25519:secp256r1"
                     : "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:"
                       "MLKEM512:MLKEM768:MLKEM1024:X25519:secp256r1",
        .show_certificates = !request->verify,
        .cancellation = cancellation,
        .diagnostics = &options};
    nm_tls_inspection result = nm_openssl_execute(&connection);
    bool success = result.observation.outcome == NM_QUANTUM_OK ||
                   result.observation.outcome == NM_QUANTUM_NEGATIVE;
    if (result.observation.outcome == NM_QUANTUM_CANCELLED ||
        result.observation.outcome == NM_QUANTUM_TIMEOUT)
        nm_cmd_output_append(&output, "OpenSSL command canceled or timed out.\n");
    else {
        nm_cmd_output_append(&output, "Protocol: %s\nCipher: %s\nNegotiated TLS group: %s\n",
                             result.observation.protocol[0] ? result.observation.protocol : "none",
                             result.observation.cipher[0]
                                 ? nm_openssl_cipher_name(result.observation.cipher)
                                 : "none",
                             result.observation.group[0] ? result.observation.group : "none");
        nm_cmd_output_append(&output, "ALPN protocol: %s\n",
                             result.observation.alpn[0] ? result.observation.alpn : "none");
        if (result.observation.summary && !request->brief)
            nm_cmd_output_append(&output, "%s\n", result.observation.summary);
        bool summary_has_trust = success && !result.observation.certificate_trusted &&
                                 !request->brief && result.observation.summary &&
                                 strstr(result.observation.summary,
                                        "; Certificate trust: not trusted");
        if (!summary_has_trust)
            nm_cmd_output_append(&output, "Certificate trust: %s\n",
                                 !success                                 ? "verification incomplete"
                                 : result.observation.certificate_trusted ? "trusted"
                                                                          : "not trusted");
        if (result.observation.certificate_pem)
            nm_cmd_output_append(&output, "%s", result.observation.certificate_pem);
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
