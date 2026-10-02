#include "processor_internal.h"
#include "quantum_cert_cmd_processor.h"
#include "quantum_connect_cmd_processor.h"
#include "cmd_processor_catalog.h"
#include "nmap_runner.h"
#include "nmap_targets.h"
#include "cmd_output.h"
#include "openssl_runner.h"
#include "cmd_processor_message.h"
#include "message_publish.h"
#include "freertos/task.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

struct cmd_test_task {
    pthread_t thread;
    void (*run)(void *);
    void *argument;
};
static atomic_bool block_probe, started;
static unsigned executions, publications, ack_count, result_count;
static int64_t monotonic_ms;
int64_t nm_quantum_now_ms(void)
{
    return monotonic_ms;
}
static bool fail_task, fail_publish;
static yyjson_mut_doc *last_response;
static void pause_ms(void)
{
    struct timespec t = {.tv_nsec = 1000000};
    nanosleep(&t, NULL);
}
static void *entry(void *arg)
{
    struct cmd_test_task *task = arg;
    task->run(task->argument);
    return NULL;
}
int xTaskCreatePinnedToCoreWithCaps(void (*run)(void *), const char *name, unsigned stack,
                                    void *argument, unsigned priority, TaskHandle_t *out, int core,
                                    unsigned caps)
{
    assert(!strcmp(name, "nm_command") && stack == 16384 && !priority && core == 1 && caps == 6);
    if (fail_task)
        return 0;
    *out = calloc(1, sizeof(**out));
    assert(*out);
    (*out)->run = run;
    (*out)->argument = argument;
    assert(!pthread_create(&(*out)->thread, NULL, entry, *out));
    return 1;
}
void vTaskSuspend(void *unused)
{
    (void)unused;
    pthread_exit(NULL);
}
void vTaskDeleteWithCaps(TaskHandle_t task)
{
    assert(!pthread_join(task->thread, NULL));
    free(task);
}
nm_tls_inspection nm_tls_inspect(const nm_tls_inspection_request *request)
{
    assert(!strcmp(request->host, "example.com"));
    if (request->mode == NM_TLS_INSPECT_HANDSHAKE) {
        monotonic_ms += 10;
        nm_tls_inspection result = {.observation.outcome = NM_QUANTUM_OK};
        snprintf(result.observation.group, sizeof(result.observation.group), "%s",
                 request->group ? request->group : "X25519MLKEM768");
        if (request->group && !strcmp(request->group, "X25519"))
            result.observation.outcome = NM_QUANTUM_NEGATIVE;
        return result;
    }
    ++executions;
    atomic_store(&started, true);
    while (atomic_load(&block_probe) && !atomic_load(request->cancellation))
        pause_ms();
    return (nm_tls_inspection){
        .observation = {
            .outcome = NM_QUANTUM_OK,
            .summary = nm_bulk_strdup(
                "Certificate PQC: yes (sig=yes, key=yes); SigAlg=ML-DSA-65; KeyAlg=ML-DSA-65")}};
}
void nm_tls_inspection_release(nm_tls_inspection *result)
{
    free(result->observation.summary);
}
nm_nmap_run_result nm_nmap_runner_scan(const nm_nmap_scan_request *request)
{
    assert(!strcmp(request->host, "example.com"));
    if (request->count == 2) {
        assert(request->show_reason && request->verbosity == 2 && request->show_open &&
               request->no_ping);
    }
    if (request->cancellation && atomic_load(request->cancellation))
        return (nm_nmap_run_result){.state = NM_NMAP_RUN_CANCELLED};
    nm_nmap_run_result result = {
        .state = NM_NMAP_RUN_COMPLETED,
        .standard_output =
            nm_bulk_strdup("Nmap scan report for example.com\nHost is up\n443/tcp open https\n"),
        .open_count = 1,
        .open_ports = {443}};
    return result;
}
void nm_nmap_runner_result_release(nm_nmap_run_result *result)
{
    free(result->standard_output);
    result->standard_output = NULL;
}
nm_nmap_run_result nm_nmap_runner_discover(const nm_nmap_discovery_request *request)
{
    assert(request && request->display_target && request->timeout_ms);
    if (request->has_ipv4_range) {
        assert(!strcmp(request->display_target, "192.168.1.7/24"));
        assert(request->first_ipv4 == UINT32_C(0xc0a80101));
        assert(request->target_count == 254);
    } else {
        assert(!strcmp(request->display_target, "192.0.2.1"));
        assert(request->target_count == 1);
    }
    return (nm_nmap_run_result){.state = NM_NMAP_RUN_COMPLETED,
                                .exit_code = 0,
                                .standard_output =
                                    nm_bulk_strdup("Nmap scan report\nHost is up\n")};
}
bool nm_esp_publish_event(const nm_esp_config *config, esp_mqtt_client_handle_t client,
                          const char *topic, yyjson_mut_val *payload, nm_message_encoding encoding,
                          const char *type)
{
    (void)client;
    assert(config && encoding == NM_MESSAGE_JSON && !strcmp(type, "ProcessorScanDataObj"));
    ++publications;
    if (fail_publish)
        return false;
    if (!strcmp(topic, "processor/out/scan-ack"))
        ++ack_count;
    else {
        assert(!strcmp(topic, "processor/out/scan-ran"));
        ++result_count;
    }
    yyjson_mut_doc_free(last_response);
    last_response = nm_json_clone(payload);
    assert(last_response);
    return true;
}
static yyjson_mut_doc *request(const char *id, const char *args)
{
    yyjson_mut_doc *doc = nm_json_new();
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    assert(nm_json_put_str(doc, root, "MessageID", id));
    assert(nm_json_put_str(doc, root, "Type", "QuantumCert"));
    assert(nm_json_put_str(doc, root, "AgentID", "test-agent"));
    assert(nm_json_put_str(doc, root, "Arguments", args));
    yyjson_mut_val *nested = yyjson_mut_obj(doc);
    assert(nm_json_put_str(doc, nested, "RootMessageID", "root-correlation"));
    assert(nm_json_put(doc, root, "LlmServiceObj", nested));
    assert(nm_json_put(doc, root, "FutureInteger", yyjson_mut_uint(doc, UINT64_MAX)));
    return doc;
}
static bool dispatch(processor *agent, const char *op, const char *id, const char *args)
{
    yyjson_mut_doc *doc = request(id, args);
    bool ok = nm_processor_cmd_dispatch(agent, op, yyjson_mut_doc_get_root(doc));
    yyjson_mut_doc_free(doc); /* proves queued request owns its fields */
    return ok;
}
static void drain(processor *agent)
{
    for (unsigned i = 0; agent->cmd_job && i < 2000; ++i) {
        nm_processor_cmd_poll(agent);
        pause_ms();
    }
    assert(!agent->cmd_job);
}
int main(void)
{
    nm_cmd_kind kind;
    assert(!nm_cmd_kind_find("Unknown", &kind));
    for (unsigned i = 0; i < NM_CMD_COUNT; ++i) {
        assert(nm_cmd_kind_find(nm_cmd_kind_type((nm_cmd_kind)i), &kind));
        assert(kind == (nm_cmd_kind)i && *nm_cmd_kind_help(kind));
    }
    uint16_t ports[64];
    size_t count;
    assert(nm_cmd_ports_parse("[443,8443;443]", ports, 64, &count, false) && count == 2);
    assert(nm_cmd_ports_parse("20-22,22", ports, 64, &count, true) && count == 3);
    assert(!nm_cmd_ports_parse("1-65535", ports, 64, &count, true));
    assert(!nm_cmd_ports_parse("65536", ports, 64, &count, true));
    assert(!nm_cmd_ports_parse("-1", ports, 64, &count, true));
    nm_cmd_output bounded;
    assert(nm_cmd_output_init(&bounded, 8));
    assert(!nm_cmd_output_append(&bounded, "too-long-output"));
    nm_cmd_result overflow = nm_cmd_output_finish(&bounded, true);
    assert(!overflow.success && overflow.output);
    free(overflow.output);
    nm_embedded_command command;
    const char *parse_error;
    nm_cmd_result invalid_request = nm_cmd_kind_run(NULL, NULL);
    assert(!invalid_request.success && invalid_request.output);
    free(invalid_request.output);
    nm_quantum_scan_command bad_scan = {.count = 21};
    invalid_request = nm_quantum_scan_cmd_run(&bad_scan, NULL);
    assert(!invalid_request.success && invalid_request.output);
    free(invalid_request.output);
    nm_nmap_command bad_nmap = {.count = 65};
    invalid_request = nm_nmap_cmd_run(&bad_nmap, NULL);
    assert(!invalid_request.success && invalid_request.output);
    free(invalid_request.output);
    assert(nm_cmd_kind_parse(NM_CMD_SCAN,
                             "--target example.com --ports '443,8443' --algorithms MLKEM768", 30000,
                             &command, &parse_error));
    assert(command.data.scan.count == 2 && command.data.scan.total_timeout_ms == 30000);
    nm_cmd_result scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "Quantum-safe ports found") &&
           strstr(scanned.output, "Port 8443"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(NM_CMD_SCAN, "--target example.com", 30000, &command, &parse_error));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "Port 443"));
    free(scanned.output);
    assert(!nm_cmd_kind_parse(NM_CMD_SCAN, "--target example.com --ports 443-445", 30000, &command,
                              &parse_error));
    assert(!nm_cmd_kind_parse(NM_CMD_SCAN, "--target example.com --nmap_options '-sU'", 30000,
                              &command, &parse_error));
    assert(nm_cmd_kind_parse(NM_CMD_INFO, "--algorithm kyber768", 30000, &command, &parse_error));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "Algorithm: mlkem768") &&
           strstr(scanned.output, "1184 bytes"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(NM_CMD_INFO, "--algorithm dilithium3", 30000, &command, &parse_error));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "Algorithm: mldsa65"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(NM_CMD_INFO, "--algorithm mlkem", 30000, &command, &parse_error));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(!scanned.success && strstr(scanned.output, "Multiple algorithms matched"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(NM_CMD_INFO, "--algorithm totallyunknown", 30000, &command,
                             &parse_error));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(!scanned.success && strstr(scanned.output, "No algorithms found"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(
        NM_CMD_OPENSSL, "s_client -connect example.com:443 -groups X25519 -verify_return_error",
        30000, &command, &parse_error));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "Negotiated TLS group: X25519"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(
        NM_CMD_OPENSSL,
        "s_client -connect '[::1]:8443' -servername example.com -groups MLKEM768:X25519", 30000,
        &command, &parse_error));
    assert(!strcmp(command.data.openssl.host, "::1") && command.data.openssl.port == 8443);
    assert(nm_cmd_kind_parse(NM_CMD_OPENSSL, "s_client -connect example.com:443 -tls1_2", 30000,
                             &command, &parse_error));
    assert(command.data.openssl.tls_version == 12);
    assert(!nm_cmd_kind_parse(NM_CMD_OPENSSL, "s_client -connect example.com:443 | openssl x509",
                              30000, &command, &parse_error));
    assert(nm_cmd_kind_parse(NM_CMD_NMAP, "-sT -Pn --open --reason -vv -p 443,8443 example.com",
                             30000, &command, &parse_error));
    assert(command.data.nmap.count == 2 && command.data.nmap.timeout_ms == 30000 &&
           command.data.nmap.no_ping && command.data.nmap.show_open &&
           command.data.nmap.show_reason && command.data.nmap.verbosity == 2);
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "443/tcp open"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(NM_CMD_NMAP, "-sn 192.168.1.7/24", 60000, &command, &parse_error));
    assert(command.data.nmap.discovery_only && command.data.nmap.has_ipv4_range &&
           command.data.nmap.target_count == 254 &&
           command.data.nmap.first_ipv4 == UINT32_C(0xc0a80101));
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success && strstr(scanned.output, "Host is up"));
    free(scanned.output);
    assert(nm_cmd_kind_parse(NM_CMD_NMAP, "-sn 192.0.2.1", 1000, &command, &parse_error));
    assert(command.data.nmap.discovery_only && !command.data.nmap.has_ipv4_range &&
           command.data.nmap.target_count == 1);
    scanned = nm_cmd_kind_run(&command, NULL);
    assert(scanned.success);
    free(scanned.output);
    nm_nmap_ipv4_range range;
    assert(nm_nmap_ipv4_cidr_parse("192.168.1.7/24", &range));
    assert(range.first_address == UINT32_C(0xc0a80101) && range.count == 254);
    assert(nm_nmap_ipv4_cidr_parse("192.168.1.4/30", &range));
    assert(range.first_address == UINT32_C(0xc0a80105) && range.count == 2);
    assert(nm_nmap_ipv4_cidr_parse("192.168.1.8/31", &range));
    assert(range.first_address == UINT32_C(0xc0a80108) && range.count == 2);
    assert(nm_nmap_ipv4_cidr_parse("192.168.1.9/32", &range));
    assert(range.first_address == UINT32_C(0xc0a80109) && range.count == 1);
    assert(!nm_nmap_ipv4_cidr_parse("192.168.1.1/23", &range));
    assert(!nm_nmap_ipv4_cidr_parse("192.168.1.256/24", &range));
    assert(!nm_nmap_ipv4_cidr_parse("192.168.1.1/24junk", &range));
    assert(
        !nm_cmd_kind_parse(NM_CMD_NMAP, "-sn -Pn 192.168.1.0/24", 60000, &command, &parse_error));
    assert(!nm_cmd_kind_parse(NM_CMD_NMAP, "-sT 192.168.1.0/24", 60000, &command, &parse_error));
    assert(
        !nm_cmd_kind_parse(NM_CMD_NMAP, "-p 80 -sn 192.168.1.0/24", 60000, &command, &parse_error));
    assert(!nm_cmd_kind_parse(NM_CMD_NMAP, "--script vuln example.com", 30000, &command,
                              &parse_error));
    assert(nm_cmd_kind_parse(NM_CMD_NMAP, "-F example.com", 30000, &command, &parse_error));
    assert(command.data.nmap.fast_scan && command.data.nmap.count == 0);
    assert(nm_cmd_kind_parse(NM_CMD_NMAP, "-sn -PR --reason -v 192.168.1.0/24", 60000, &command,
                             &parse_error));
    assert(command.data.nmap.arp_only && command.data.nmap.show_reason &&
           command.data.nmap.verbosity == 1 && command.data.nmap.target_count == 254);
    const char *bad_nmap_args[] = {
        "-PR -Pn host.test", "-sn -sT host.test",    "-sn -sV host.test",
        "-sn -F host.test",  "-sn --open host.test", "-p80 host.test '' --script vuln",
        "-p80, host.test",   "-p80,,443 host.test",  "-p80:443 host.test",
        "-p+80 host.test",   "nmap nmap host.test",  "host.test;evil",
        "host.test|evil",    "-sn 192.168.01.0/24",  "192.168.01.7",
        "192.168.999.1"};
    for (size_t i = 0; i < sizeof(bad_nmap_args) / sizeof(*bad_nmap_args); ++i)
        assert(!nm_cmd_kind_parse(NM_CMD_NMAP, bad_nmap_args[i], 30000, &command, &parse_error));
    assert(!strcmp(nm_openssl_group_name("x25519_mlkem768"), "X25519MLKEM768"));
    assert(!strcmp(nm_openssl_group_name("ML-KEM-768"), "MLKEM768"));
    assert(!nm_openssl_group_name("x25519_mlkem512"));
    assert(!nm_openssl_group_name("kyber768"));
    nm_quantum_connect_command connect;
    const char *connect_error;
    assert(nm_quantum_connect_cmd_parse(
        "--target example.com --algorithms 'MLKEM768;mlkem768:X25519MLKEM768' --port 8443",
        &connect, &connect_error));
    assert(connect.count == 2 && connect.connection.port == 8443);
    nm_cmd_result connected = nm_quantum_connect_cmd_run(&connect, NULL);
    assert(connected.success && strstr(connected.output, "group=MLKEM768"));
    free(connected.output);
    assert(nm_quantum_connect_cmd_parse("--target example.com --algorithms frodo640aes", &connect,
                                        &connect_error));
    connected = nm_quantum_connect_cmd_run(&connect, NULL);
    assert(!connected.success && strstr(connected.output, "Unsupported TLS group"));
    free(connected.output);
    assert(!nm_quantum_connect_cmd_parse("--target example.com --port 65536", &connect,
                                         &connect_error));
    assert(nm_quantum_connect_cmd_parse("--target example.com", &connect, &connect_error));
    assert(connect.count == 6);
    atomic_bool canceled = true;
    connected = nm_quantum_connect_cmd_run(&connect, &canceled);
    assert(!connected.success && strstr(connected.output, "canceled"));
    free(connected.output);
    nm_quantum_cert_command parsed;
    const char *error;
    assert(nm_quantum_cert_cmd_parse("--target HTTPS://example.com///", &parsed, &error));
    assert(!strcmp(parsed.target, "example.com") && parsed.port == 443 &&
           parsed.timeout_ms == 59000);
    assert(nm_quantum_cert_cmd_parse("-target 'example.com' --PORT=8443 --timeout 15000", &parsed,
                                     &error));
    assert(parsed.port == 8443 && parsed.timeout_ms == 15000);
    const char *bad[] = {"",
                         "example.com",
                         "--target example.com --port 65536",
                         "--target example.com --timeout 9999999999999999999999999",
                         "--target example.com --timeout -1",
                         "--target example.com --unknown 2",
                         "--target 'example.com",
                         "--target example.com/path"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(!nm_quantum_cert_cmd_parse(bad[i], &parsed, &error));
    yyjson_mut_doc *doc = request("format", "");
    assert(nm_cmd_message_format(doc, "one\r\n\ntwo\nthree", true, 2));
    const char *out = string_field(yyjson_mut_doc_get_root(doc), "ScanCommandOutput");
    assert(!strcmp(out,
                   "one\\ntwo\\n[Showing page 1 of 2. Total lines: 3.]\\n[Output truncated to 2 "
                   "lines per page. Choose another page or refine the query for less data.]\\n"));
    yyjson_mut_doc_free(doc);
    char bounded_lines[32768];
    size_t bounded_used = 0;
    for (unsigned i = 0; i < 256; ++i) {
        int n =
            snprintf(bounded_lines + bounded_used, sizeof(bounded_lines) - bounded_used,
                     "host-%03u is up; MAC Address: 02:03:04:05:06:07; reason=arp-response\n", i);
        assert(n > 0 && (size_t)n < sizeof(bounded_lines) - bounded_used);
        bounded_used += (size_t)n;
    }
    doc = request("format-256-lines", "");
    assert(nm_cmd_message_format(doc, bounded_lines, true, 256));
    out = string_field(yyjson_mut_doc_get_root(doc), "ScanCommandOutput");
    assert(bounded_used > 8192);
    assert(strstr(out, "host-255 is up; MAC Address:"));
    yyjson_mut_doc_free(doc);
    nm_esp_config config = {.app_id = "test-agent"};
    processor agent = {.config = &config};
    atomic_init(&agent.connected, true);
    assert(dispatch(&agent, "getCmdProcessorList", "list", ""));
    assert(strstr(string_field(yyjson_mut_doc_get_root(last_response), "ScanCommandOutput"),
                  "'QuantumCert'"));
    assert(dispatch(&agent, "getCmdProcessorHelp", "help", ""));
    assert(dispatch(&agent, "processorCommand", "valid", "--target example.com"));
    drain(&agent);
    assert(executions == 1);
    yyjson_mut_val *root = yyjson_mut_doc_get_root(last_response);
    assert(yyjson_mut_get_bool(yyjson_mut_obj_get(root, "ScanCommandSuccess")));
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(root, "FutureInteger")) == UINT64_MAX);
    assert(!strcmp(string_field(yyjson_mut_obj_get(root, "LlmServiceObj"), "RootMessageID"),
                   "root-correlation"));
    assert(dispatch(&agent, "processorCommand", "valid", "--target example.com"));
    assert(executions == 1 && !agent.cmd_job);
    atomic_store(&block_probe, true);
    atomic_store(&started, false);
    assert(dispatch(&agent, "processorCommand", "cancel-me", "--target example.com"));
    while (!atomic_load(&started))
        pause_ms();
    assert(dispatch(&agent, "processorCommand", "busy", "--target example.com"));
    assert(
        strstr(string_field(yyjson_mut_doc_get_root(last_response), "ScanCommandOutput"), "busy"));
    assert(dispatch(&agent, "cancelCommand", "cancel-me", ""));
    drain(&agent);
    assert(strstr(string_field(yyjson_mut_doc_get_root(last_response), "ScanCommandOutput"),
                  "canceled or timed out"));
    atomic_store(&block_probe, false);
    fail_task = true;
    assert(dispatch(&agent, "processorCommand", "no-worker", "--target example.com"));
    assert(!agent.cmd_job);
    fail_task = false;
    fail_publish = true;
    assert(dispatch(&agent, "processorCommand", "retry", "--target example.com"));
    nm_processor_cmd_poll(&agent);
    assert(agent.cmd_job);
    fail_publish = false;
    drain(&agent);
    assert(ack_count && result_count && publications > ack_count + result_count);
    const char *runtime_args[] = {"--target example.com",
                                  "--target example.com --algorithms MLKEM768",
                                  "--target example.com --ports 443",
                                  "--algorithm mlkem768",
                                  "version",
                                  "-p 443 example.com"};
    for (unsigned i = 0; i < NM_CMD_COUNT; ++i) {
        char id[32];
        snprintf(id, sizeof(id), "all-command-%u", i);
        yyjson_mut_doc *message = request(id, runtime_args[i]);
        assert(nm_json_put_str(message, yyjson_mut_doc_get_root(message), "Type",
                               nm_cmd_kind_type((nm_cmd_kind)i)));
        assert(nm_processor_cmd_dispatch(&agent, "processorCommand",
                                         yyjson_mut_doc_get_root(message)));
        yyjson_mut_doc_free(message);
        drain(&agent);
        assert(yyjson_mut_get_bool(
            yyjson_mut_obj_get(yyjson_mut_doc_get_root(last_response), "ScanCommandSuccess")));
    }
    yyjson_mut_doc_free(last_response);
    puts("QuantumCert parser, formatting, worker ownership, cancellation, busy/dedup and retry "
         "passed");
}
