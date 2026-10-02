/* Offline adapter tests: every task, ping, HTTP, DNS and socket operation is
 * replaced below. Including the implementation exposes its lifetime paths.
 * Build from repository root (no ESP-IDF or live network required):
 * cc -std=c17 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror -UNDEBUG \
 *   -fsanitize=address,undefined -Itests/native/endpoint_stubs \
 *   -Ithird_party/yyjson/src -Ifirmware/main tests/native/test_endpoint_execution.c \
 *   firmware/main/monitor_model.c firmware/main/monitor_record.c \
 *   firmware/main/monitor_snapshot.c firmware/main/monitor_numbers.c \
 *   firmware/main/monitor_schedule.c third_party/yyjson/src/yyjson.c -lm -o
 * /tmp/test_endpoint_execution
 */
/* Include libc declarations before renaming. Inheriting libc's leaf/pure
 * attributes is invalid for mocks that deliberately mutate the fake clock. */
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
int test_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
void test_freeaddrinfo(struct addrinfo *);
int test_socket(int, int, int);
int test_connect(int, const struct sockaddr *, socklen_t);
int test_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int test_getsockopt(int, int, int, void *, socklen_t *);
int test_fcntl(int, int, ...);
int test_close(int);
#define getaddrinfo test_getaddrinfo
#define freeaddrinfo test_freeaddrinfo
#define socket test_socket
#define connect test_connect
#define select test_select
#define getsockopt test_getsockopt
#define fcntl test_fcntl
#define close test_close
#include "../../firmware/main/endpoint_common.c"
#include "../../firmware/main/endpoint_dns.c"
#include "../../firmware/main/endpoint_icmp.c"
#include "../../firmware/main/endpoint_tcp.c"
#include "../../firmware/main/endpoint_nmap.c"
#include "../../firmware/main/nmap_runner_embedded.c"
#include "../../firmware/main/nmap_targets.c"
#include "../../firmware/main/endpoint_http.c"
#include "../../firmware/main/endpoints.c"
#include <assert.h>
#include <pthread.h>
#include <sched.h>

/* Clock reads must remain observable across mocked platform calls, just as
 * the real timer can advance outside the endpoint translation unit. */
static volatile int64_t now_us;
struct nm_http_deadline {
    int64_t until;
};
static unsigned http_deadlines;
static bool http_resource_failure;
bool nm_http_deadline_resource_failed(const nm_http_deadline *d)
{
    assert(d);
    return http_resource_failure;
}
nm_http_deadline *nm_http_deadline_new(unsigned ms, nm_http_resolver resolver)
{
    assert(resolver);
    nm_http_deadline *d = malloc(sizeof(*d));
    assert(d);
    d->until = now_us + (int64_t)ms * 1000;
    ++http_deadlines;
    return d;
}
esp_transport_handle_t nm_http_deadline_transport(nm_http_deadline *d)
{
    return d;
}
void nm_http_deadline_bind(nm_http_deadline *d, esp_http_client_handle_t c)
{
    assert(d && c);
}
bool nm_http_deadline_expired(nm_http_deadline *d)
{
    return now_us >= d->until;
}
void nm_http_deadline_free(nm_http_deadline *d)
{
    assert(http_deadlines);
    --http_deadlines;
    free(d);
}
static unsigned semaphores, address_lists, sockets, http_clients, ping_sessions;
static bool dns_complete = true, ping_complete = true, dns_empty, dns_error;
static bool dns_memory_error;
static int socket_resource_error;
static int connect_resource_error, socket_option_error;
static atomic_bool *cancel_after_wait;
static bool task_error, semaphore_error, ping_new_error, ping_start_error;
static bool ipv6_first, http_init_error, ping_reply = true;
static int http_status = 200, http_error, http_errno;
static int64_t http_length = 12;
static char http_url[1200];
static int socket_family, connect_mode;
static bool nmap_test_mode;
static uint16_t nmap_open_port;
static unsigned nmap_connects;
static nm_nmap_arp_state arp_state = NM_ARP_OFF_LINK;
static unsigned arp_probes;
nm_nmap_arp_result nm_nmap_arp_probe(uint32_t ipv4, unsigned timeout_ms,
                                     const atomic_bool *cancellation)
{
    (void)ipv4;
    (void)timeout_ms;
    ++arp_probes;
    return (nm_nmap_arp_result){
        .state = cancellation && atomic_load(cancellation) ? NM_ARP_CANCELLED : arp_state,
        .mac = {2, 3, 4, 5, 6, 7}};
}
static unsigned select_calls;
static const nm_monitor_record *ble_monitor_seen;
static unsigned ble_timeout_seen;
nm_esp_result nm_endpoint_check_quantum(const char *host, const char *type, unsigned port,
                                        unsigned timeout)
{
    (void)host;
    (void)type;
    (void)port;
    (void)timeout;
    return (nm_esp_result){.ok = true};
}
nm_esp_result nm_endpoint_check_ble(const nm_monitor_record *monitor, unsigned timeout)
{
    ble_monitor_seen = monitor;
    ble_timeout_seen = timeout;
    return (nm_esp_result){.ok = true, .elapsed_ms = 23};
}
enum { TCP_IMMEDIATE, TCP_PENDING, TCP_TIMEOUT, TCP_REFUSED, TCP_IPV6_FALLBACK };
typedef struct {
    void (*function)(void *);
    void *arg;
} fake_task;
static fake_task pending_dns[NM_ENDPOINT_MAX_OPERATIONS];
bool nm_dns_tasks_init(void)
{
    return true;
}
bool nm_dns_task_start(void (*run)(void *), void *arg)
{
    return xTaskCreate(run, "nm_dns", 4096, arg, 1, NULL) == pdPASS;
}
void nm_dns_task_finish(void)
{
    nm_endpoint_release_slot();
}
typedef struct {
    esp_ping_callbacks_t callbacks;
    bool started;
    int family;
} fake_ping;
static fake_ping *pending_ping[NM_ENDPOINT_MAX_OPERATIONS];
static void (*on_delay)(void);
void vTaskDelay(TickType_t ticks)
{
    now_us += (int64_t)ticks * 1000;
    if (cancel_after_wait)
        atomic_store(cancel_after_wait, true);
    if (on_delay)
        on_delay();
}

int64_t esp_timer_get_time(void)
{
    return now_us;
}
const char *esp_err_to_name(esp_err_t error)
{
    return error == ESP_OK ? "ESP_OK" : "ESP_FAIL";
}
SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    if (semaphore_error)
        return NULL;
    int *value = calloc(1, sizeof(*value));
    assert(value);
    ++semaphores;
    return value;
}
int xSemaphoreGive(SemaphoreHandle_t semaphore)
{
    *(int *)semaphore = 1;
    return pdTRUE;
}
void vSemaphoreDelete(SemaphoreHandle_t semaphore)
{
    assert(semaphores);
    --semaphores;
    free(semaphore);
}
int xTaskCreate(void (*function)(void *), const char *name, unsigned stack, void *arg,
                unsigned priority, void *handle)
{
    (void)name;
    (void)stack;
    (void)priority;
    (void)handle;
    if (task_error)
        return 0;
    for (size_t i = 0; i < NM_ENDPOINT_MAX_OPERATIONS; ++i)
        if (!pending_dns[i].function) {
            pending_dns[i] = (fake_task){function, arg};
            return pdPASS;
        }
    assert(false);
    return 0;
}
void vTaskDelete(void *task)
{
    assert(!task);
}
static void finish_dns(size_t i)
{
    fake_task task = pending_dns[i];
    assert(task.function);
    pending_dns[i] = (fake_task){0};
    task.function(task.arg);
}
static void finish_ping(size_t i)
{
    fake_ping *ping = pending_ping[i];
    assert(ping && ping->started);
    pending_ping[i] = NULL;
    esp_ping_callbacks_t callbacks = ping->callbacks;
    if (ping_reply)
        callbacks.on_ping_success(ping, callbacks.cb_args);
    callbacks.on_ping_end(ping, callbacks.cb_args);
    /* ping and callback context may now be freed; never inspect either. */
}
int xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks)
{
    for (size_t i = 0; i < NM_ENDPOINT_MAX_OPERATIONS; ++i) {
        if (dns_complete && pending_dns[i].function &&
            ((dns_context *)pending_dns[i].arg)->done == semaphore)
            finish_dns(i);
        if (ping_complete && pending_ping[i] &&
            ((ping_context *)pending_ping[i]->callbacks.cb_args)->done == semaphore)
            finish_ping(i);
    }
    if (*(int *)semaphore) {
        *(int *)semaphore = 0;
        return pdTRUE;
    }
    now_us += (int64_t)ticks * 1000;
    if (cancel_after_wait)
        atomic_store(cancel_after_wait, true);
    return 0;
}
static struct addrinfo *make_address(int family)
{
    struct addrinfo *address = calloc(1, sizeof(*address));
    assert(address);
    address->ai_family = family;
    address->ai_socktype = SOCK_STREAM;
    address->ai_addrlen =
        family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    address->ai_addr = calloc(1, address->ai_addrlen);
    assert(address->ai_addr);
    address->ai_addr->sa_family = (sa_family_t)family;
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)address->ai_addr;
        assert(inet_pton(AF_INET, "192.0.2.1", &v4->sin_addr) == 1);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)address->ai_addr;
        assert(inet_pton(AF_INET6, "2001:db8::1", &v6->sin6_addr) == 1);
    }
    return address;
}
int test_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints,
                     struct addrinfo **out)
{
    assert(strcmp(host, "host.test") == 0); /* checks copied input after timeout */
    if (service) {
        char *end = NULL;
        long port = strtol(service, &end, 10);
        assert(end && !*end && port > 0 && port <= UINT16_MAX);
    }
    assert(hints->ai_family == AF_UNSPEC);
    now_us += 5000;
    if (dns_memory_error)
        return EAI_MEMORY;
    if (dns_error)
        return EAI_FAIL;
    if (dns_empty) {
        *out = NULL;
        return 0;
    }
    *out = make_address(ipv6_first ? AF_INET6 : AF_INET);
    if (ipv6_first)
        (*out)->ai_next = make_address(AF_INET);
    ++address_lists;
    return 0;
}
void test_freeaddrinfo(struct addrinfo *addresses)
{
    assert(address_lists);
    --address_lists;
    while (addresses) {
        struct addrinfo *next = addresses->ai_next;
        free(addresses->ai_addr);
        free(addresses);
        addresses = next;
    }
}
int ipaddr_aton(const char *text, ip_addr_t *address)
{
    address->family = strchr(text, ':') ? AF_INET6 : AF_INET;
    return inet_pton(address->family, text, address->bytes);
}
esp_err_t esp_ping_new_session(const esp_ping_config_t *config,
                               const esp_ping_callbacks_t *callbacks, esp_ping_handle_t *out)
{
    assert(config->count == 1 && config->interval_ms == 0 && config->timeout_ms > 0);
    if (ping_new_error || (ipv6_first && config->target_addr.family == AF_INET6))
        return ESP_FAIL;
    fake_ping *ping = calloc(1, sizeof(*ping));
    assert(ping);
    ping->callbacks = *callbacks;
    ping->family = config->target_addr.family;
    *out = ping;
    ++ping_sessions;
    return ESP_OK;
}
esp_err_t esp_ping_start(esp_ping_handle_t handle)
{
    if (ping_start_error)
        return ESP_FAIL;
    fake_ping *ping = handle;
    ping->started = true;
    for (size_t i = 0; i < NM_ENDPOINT_MAX_OPERATIONS; ++i)
        if (!pending_ping[i]) {
            pending_ping[i] = ping;
            return ESP_OK;
        }
    assert(false);
    return ESP_FAIL;
}
esp_err_t esp_ping_delete_session(esp_ping_handle_t handle)
{
    assert(ping_sessions);
    --ping_sessions;
    free(handle);
    return ESP_OK;
}
esp_err_t esp_ping_get_profile(esp_ping_handle_t handle, int profile, void *value, uint32_t size)
{
    assert(handle && profile == ESP_PING_PROF_TIMEGAP && size == sizeof(uint32_t));
    *(uint32_t *)value = 17;
    return ESP_OK;
}
int test_socket(int family, int type, int protocol)
{
    if (socket_resource_error) {
        errno = socket_resource_error;
        return -1;
    }
    (void)protocol;
    assert(type == SOCK_STREAM);
    socket_family = family;
    ++sockets;
    return 3;
}
int test_fcntl(int fd, int command, ...)
{
    assert(fd == 3 && (command == F_GETFL || command == F_SETFL));
    return 0;
}
int test_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)length;
    assert(fd == 3 && address->sa_family == socket_family);
    if (connect_resource_error) {
        errno = connect_resource_error;
        return -1;
    }
    if (nmap_test_mode) {
        uint16_t port = socket_family == AF_INET
                            ? ntohs(((const struct sockaddr_in *)address)->sin_port)
                            : ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
        ++nmap_connects;
        now_us += 7000;
        if (nmap_open_port && port == nmap_open_port)
            return 0;
        errno = ECONNREFUSED;
        return -1;
    }
    now_us += 7000;
    if (connect_mode == TCP_REFUSED ||
        (connect_mode == TCP_IPV6_FALLBACK && socket_family == AF_INET6)) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (connect_mode == TCP_PENDING || connect_mode == TCP_TIMEOUT) {
        errno = EINPROGRESS;
        return -1;
    }
    return 0;
}
int test_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *timeout)
{
    (void)r;
    (void)e;
    assert(n == 4 && FD_ISSET(3, w));
    ++select_calls;
    if (connect_mode == TCP_TIMEOUT) {
        now_us += timeout->tv_sec * INT64_C(1000000) + timeout->tv_usec;
        if (cancel_after_wait)
            atomic_store(cancel_after_wait, true);
        return 0;
    }
    return 1;
}
int test_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
    assert(fd == 3 && level == SOL_SOCKET && option == SO_ERROR && *length == sizeof(int));
    if (socket_option_error) {
        errno = socket_option_error;
        return -1;
    }
    *(int *)value = 0;
    return 0;
}
int test_close(int fd)
{
    assert(fd == 3 && sockets);
    --sockets;
    return 0;
}
int esp_crt_bundle_attach(void *config)
{
    (void)config;
    return ESP_OK;
}
esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *config)
{
    assert(config->crt_bundle_attach == esp_crt_bundle_attach && config->method == HTTP_METHOD_GET);
    snprintf(http_url, sizeof(http_url), "%s", config->url);
    if (http_init_error)
        return NULL;
    ++http_clients;
    return malloc(1);
}
esp_err_t esp_http_client_perform(esp_http_client_handle_t client)
{
    assert(client);
    now_us += 11000;
    return http_error;
}
int esp_http_client_get_status_code(esp_http_client_handle_t client)
{
    assert(client);
    return http_status;
}
int esp_http_client_get_errno(esp_http_client_handle_t client)
{
    assert(client);
    return http_errno;
}
int64_t esp_http_client_get_content_length(esp_http_client_handle_t client)
{
    assert(client);
    return http_length;
}
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client)
{
    assert(http_clients);
    --http_clients;
    free(client);
    return ESP_OK;
}

static nm_esp_result run(const char *json)
{
    yyjson_mut_doc *doc = nm_json_read(json, strlen(json));
    assert(doc);
    nm_monitor_record *monitor =
        (nm_monitor_record *)nm_record_decode(NM_MONITOR, yyjson_mut_doc_get_root(doc));
    nm_esp_result result = nm_esp_endpoint_run(monitor);
    nm_record_release((nm_record *)monitor);
    yyjson_mut_doc_free(doc);
    return result;
}
static void clean(void)
{
    assert(!semaphores && !address_lists && !sockets && !http_clients && !ping_sessions &&
           !http_deadlines);
    assert(atomic_load(&outstanding_operations) == 0);
}
static void free_dns_slot(void)
{
    on_delay = NULL;
    finish_dns(0);
    dns_complete = true;
}
static void free_ping_slot(void)
{
    on_delay = NULL;
    finish_ping(0);
    ping_complete = true;
}
static void admission(void)
{
    dns_complete = false;
    (void)nm_endpoint_check_dns("host.test", 10);
    (void)nm_endpoint_check_dns("host.test", 10);
    int64_t start = now_us;
    nm_esp_result result = nm_endpoint_check_dns("host.test", 10);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE && now_us - start == 10000);
    on_delay = free_dns_slot;
    result = nm_endpoint_check_dns("host.test", 100);
    assert(result.ok);
    finish_dns(1);
    clean();
    ping_complete = false;
    (void)nm_endpoint_check_icmp("192.0.2.1", 10);
    (void)nm_endpoint_check_icmp("192.0.2.1", 10);
    start = now_us;
    result = nm_endpoint_check_icmp("192.0.2.1", 10);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE && now_us - start == 10000);
    on_delay = free_ping_slot;
    result = nm_endpoint_check_icmp("192.0.2.1", 100);
    assert(result.ok);
    finish_ping(1);
    clean();
}
static void lifetimes(void)
{
    admission();
    dns_complete = false;
    nm_esp_result result =
        run("{\"Address\":\"host.test\",\"EndPointType\":\"dns\",\"Timeout\":10}");
    assert(!result.ok && strcmp(result.status, "Exception") == 0 && semaphores == 1);
    assert(strstr(result.message, "Timeout while resolving"));
    (void)nm_endpoint_check_dns("host.test", 10);
    result = nm_endpoint_check_dns("host.test", 10);
    assert(!result.ok && strstr(result.message, "busy") && semaphores == 2);
    finish_dns(0);
    finish_dns(1);
    clean(); /* late writes after caller/doc destruction */
    dns_complete = true;
    ping_complete = false;
    result = nm_endpoint_check_icmp("192.0.2.1", 10);
    assert(!result.ok && strcmp(result.message, "ICMP: Failed to connect: TimedOut") == 0);
    assert(semaphores == 1 && ping_sessions == 1);
    (void)nm_endpoint_check_icmp("192.0.2.1", 10);
    result = nm_endpoint_check_icmp("192.0.2.1", 10);
    assert(!result.ok && strstr(result.message, "busy") && semaphores == 2);
    finish_ping(0);
    finish_ping(1);
    clean(); /* both success and end may be late */
    ping_complete = true;
    result = nm_endpoint_check_icmp("192.0.2.1", 100);
    assert(result.ok && result.elapsed_ms == 17 && strcmp(result.status, "Success") == 0);
    clean();
    ping_reply = false;
    result = nm_endpoint_check_icmp("192.0.2.1", 100);
    assert(!result.ok);
    clean();
    ping_reply = true;
    task_error = true;
    result = nm_endpoint_check_dns("host.test", 100);
    assert(!result.ok);
    clean();
    task_error = false;
    semaphore_error = true;
    result = nm_endpoint_check_dns("host.test", 100);
    assert(!result.ok);
    clean();
    result = nm_endpoint_check_icmp("192.0.2.1", 100);
    assert(!result.ok);
    clean();
    semaphore_error = false;
    ping_new_error = true;
    result = nm_endpoint_check_icmp("192.0.2.1", 100);
    assert(!result.ok);
    clean();
    ping_new_error = false;
    ping_start_error = true;
    result = nm_endpoint_check_icmp("192.0.2.1", 100);
    assert(!result.ok);
    clean();
    ping_start_error = false;
}
static void results(void)
{
    nm_esp_result result = nm_endpoint_check_dns("host.test", 100);
    assert(result.ok && result.elapsed_ms == 5);
    assert(strcmp(result.message, "Found IP Addresses  : 192.0.2.1") == 0);
    clean();
    dns_empty = true;
    result = nm_endpoint_check_dns("host.test", 100);
    assert(!result.ok && strcmp(result.status, "Exception") == 0);
    result = nm_endpoint_check_tcp("host.test", 0, 100);
    assert(!result.ok && strcmp(result.status, "Unable to resolve domain.") == 0);
    clean();
    dns_empty = false;
    dns_error = true;
    result = nm_endpoint_check_dns("host.test", 100);
    assert(!result.ok);
    clean();
    dns_error = false;
    dns_memory_error = true;
    result = nm_endpoint_check_dns("host.test", 100);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
    clean();
    dns_memory_error = false;
    const int local_errors[] = {ENOMEM, ENOBUFS, EMFILE, ENFILE};
    for (size_t i = 0; i < sizeof(local_errors) / sizeof(local_errors[0]); ++i) {
        socket_resource_error = local_errors[i];
        result = nm_endpoint_check_tcp("host.test", 0, 100);
        assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
        clean();
    }
    socket_resource_error = 0;
    result = nm_endpoint_check_tcp("host.test", 0, 100);
    assert(result.ok && result.elapsed_ms == 7 && strcmp(result.status, "Connected") == 0);
    assert(select_calls == 0);
    clean();
    connect_mode = TCP_PENDING;
    result = nm_endpoint_check_tcp("host.test", 0, 100);
    assert(result.ok && result.elapsed_ms == 7);
    clean();
    connect_mode = TCP_TIMEOUT;
    int64_t start = now_us;
    result = nm_endpoint_check_tcp("host.test", 0, 100);
    assert(!result.ok && strcmp(result.status, "Connection timed out.") == 0);
    assert(now_us - start == 100000);
    clean();
    connect_mode = TCP_REFUSED;
    result = nm_endpoint_check_tcp("host.test", 0, 100);
    assert(!result.ok && strcmp(result.status, "Exception") == 0);
    clean();
    ipv6_first = true;
    connect_mode = TCP_IPV6_FALLBACK;
    result = nm_endpoint_check_tcp("host.test", 0, 100);
    assert(result.ok && result.elapsed_ms == 14);
    clean();
    result = nm_endpoint_check_icmp("host.test", 100);
    assert(result.ok && result.elapsed_ms == 17);
    clean();
    ipv6_first = false;
    connect_mode = TCP_IMMEDIATE;
    result = nm_endpoint_check_http("host.test/path", "https", 8443, 100);
    assert(result.ok && strcmp(http_url, "https://host.test:8443/path") == 0);
    assert(strcmp(result.message, "OK") == 0 && result.elapsed_ms == 11);
    clean();
    http_status = 404;
    result = nm_endpoint_check_http("http://host.test/path", "httphtml", 8080, 100);
    assert(result.ok && strcmp(http_url, "http://host.test:8080/path") == 0);
    assert(strcmp(result.message, "NotFound  : 12 bytes read") == 0);
    clean();
    http_status = 600;
    result = nm_endpoint_check_http("host.test", "http", 0, 100);
    assert(result.ok && strcmp(result.status, "600") == 0);
    clean();
    http_status = 200;
    http_error = ESP_ERR_TIMEOUT;
    result = nm_endpoint_check_http("host.test", "http", 0, 100);
    assert(!result.ok && strcmp(result.status, "Timeout") == 0);
    assert(strcmp(result.message, "HTTP: Failed to connect: Timed out after 100") == 0);
    clean();
    http_error = ESP_FAIL;
    result = nm_endpoint_check_http("host.test", "http", 0, 100);
    assert(!result.ok && strcmp(result.status, "HttpRequestException") == 0);
    clean();
    http_error = ESP_OK;
    /* A completed response past the total deadline must not be reported up. */
    result = nm_endpoint_check_http("host.test", "http", 0, 5);
    assert(!result.ok && strcmp(result.status, "Timeout") == 0);
    clean();
    http_error = ESP_ERR_HTTP_READ_TIMEOUT;
    result = nm_endpoint_check_http("host.test", "http", 0, 100);
    assert(!result.ok && strcmp(result.status, "Timeout") == 0);
    clean();
    http_error = ESP_OK;
    http_init_error = true;
    result = nm_endpoint_check_http("host.test", "http", 0, 100);
    assert(!result.ok && result.disposition == NM_PROBE_LOCAL_FAILURE);
    clean();
    http_init_error = false;
    http_error = ESP_FAIL;
    http_resource_failure = true;
    result = nm_endpoint_check_http("host.test", "https", 0, 100);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
    clean();
    http_resource_failure = false;
    http_error = ESP_ERR_NO_MEM;
    result = nm_endpoint_check_http("host.test", "https", 0, 100);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
    clean();
    http_error = ESP_OK;
    result = nm_endpoint_check_http("http:///bad", "http", 0, 100);
    assert(!result.ok && strcmp(result.status, "Exception") == 0);
    clean();
}
static void strict_numbers(void)
{
    /* Canonical monitor info uses signed constructors for positive ints. */
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    assert(doc);
    yyjson_mut_val *monitor = yyjson_mut_obj(doc);
    assert(yyjson_mut_obj_add_str(doc, monitor, "Address", "host.test"));
    assert(yyjson_mut_obj_add_str(doc, monitor, "EndPointType", "http"));
    assert(yyjson_mut_obj_add_sint(doc, monitor, "Timeout", 59000));
    assert(yyjson_mut_obj_add_sint(doc, monitor, "Port", 8080));
    nm_monitor_record *typed = (nm_monitor_record *)nm_record_decode(NM_MONITOR, monitor);
    nm_esp_result signed_result = nm_esp_endpoint_run(typed);
    nm_record_release((nm_record *)typed);
    assert(signed_result.ok && strcmp(http_url, "http://host.test:8080/") == 0);
    yyjson_mut_doc_free(doc);
    clean();
    const char *invalid[] = {"1.0", "1e0", "-1", "null", "true", "\"80\"", "4294967296"};
    const char *fields[] = {"Timeout", "Port"};
    char json[256];
    for (size_t f = 0; f < 2; ++f)
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            snprintf(json, sizeof(json),
                     "{\"Address\":\"host.test\",\"EndPointType\":\"http\",\"%s\":%s}", fields[f],
                     invalid[i]);
            nm_esp_result result = run(json);
            assert(!result.ok && strcmp(result.status, "Exception") == 0 &&
                   strstr(result.message, "Invalid monitor"));
            clean();
        }
    nm_esp_result result =
        run("{\"Address\":\"host.test\",\"EndPointType\":\"http\",\"Port\":65536}");
    assert(!result.ok);
    clean();
}

static void nmap_endpoint(void)
{
    assert(nm_esp_endpoint_supported("nmap"));
    assert(!nm_esp_endpoint_supported("nmapvuln"));
    nm_monitor_record monitor = {
        .Address = "https://host.test/status", .EndPointType = "nmap", .Port = 443, .Timeout = 100};
    nmap_test_mode = true;
    nmap_open_port = 443;
    nmap_connects = 0;
    nm_esp_result result = nm_esp_endpoint_run(&monitor);
    assert(result.ok && !strcmp(result.status, "Port/s open"));
    assert(result.detail_message && strstr(result.detail_message, "443/tcp open"));
    assert(strstr(result.detail_message, "Host is up"));
    assert(nmap_connects == 1);
    nm_esp_result_release(&result);
    clean();

    monitor.Port = 0;
    nmap_open_port = 80;
    nmap_connects = 0;
    result = nm_esp_endpoint_run(&monitor);
    assert(result.ok && !strcmp(result.status, "Port/s open"));
    assert(result.detail_message && strstr(result.detail_message, "80/tcp open"));
    assert(nmap_connects == 22);
    nm_esp_result_release(&result);
    clean();

    nm_nmap_scan_request fast_scan = {.host = "host.test", .timeout_ms = 10000, .fast_scan = true};
    nmap_connects = 0;
    nm_nmap_run_result fast_result = nm_nmap_runner_scan(&fast_scan);
    assert(fast_result.state == NM_NMAP_RUN_COMPLETED && nmap_connects == 8);
    nm_nmap_runner_result_release(&fast_result);
    clean();

    const uint16_t reason_port = 443;
    nm_nmap_scan_request detailed_scan = {.host = "host.test",
                                          .ports = &reason_port,
                                          .count = 1,
                                          .timeout_ms = 1000,
                                          .show_reason = true,
                                          .verbosity = 2};
    nmap_open_port = reason_port;
    nm_nmap_run_result detailed_result = nm_nmap_runner_scan(&detailed_scan);
    assert(detailed_result.state == NM_NMAP_RUN_COMPLETED);
    assert(strstr(detailed_result.standard_output, "REASON"));
    assert(strstr(detailed_result.standard_output, "connect"));
    assert(strstr(detailed_result.standard_output, "Scanned 1 TCP ports"));
    nm_nmap_runner_result_release(&detailed_result);
    clean();

    monitor.Port = 1883;
    nmap_open_port = 0;
    nmap_connects = 0;
    result = nm_esp_endpoint_run(&monitor);
    assert(result.ok && strstr(result.detail_message, "Host is up"));
    assert(strstr(result.detail_message, "1883/tcp closed"));
    assert(nmap_connects == 1);
    nm_esp_result_release(&result);
    clean();

    const uint16_t filtered_port = 1883;
    nm_nmap_scan_request open_only = {.host = "host.test",
                                      .ports = &filtered_port,
                                      .count = 1,
                                      .timeout_ms = 1000,
                                      .show_open = true};
    nm_nmap_run_result open_only_result = nm_nmap_runner_scan(&open_only);
    assert(open_only_result.state == NM_NMAP_RUN_COMPLETED);
    assert(strstr(open_only_result.standard_output, "Host is up"));
    assert(!strstr(open_only_result.standard_output, "PORT     STATE"));
    nm_nmap_runner_result_release(&open_only_result);
    clean();

    /* The process-like adapter accepts only the command shape this endpoint
     * constructs; arbitrary flags (including vuln scripts) cannot be injected. */
    const char *unsupported_args[] = {"nmap", "--script", "vuln", "host.test"};
    unsigned connects_before_unsupported = nmap_connects;
    nm_nmap_run_result rejected = nm_nmap_runner_execute(unsupported_args, 4, 100);
    assert(rejected.state == NM_NMAP_RUN_ERROR);
    assert(nmap_connects == connects_before_unsupported);
    nm_nmap_runner_result_release(&rejected);

    socket_resource_error = EMFILE;
    result = nm_esp_endpoint_run(&monitor);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
    socket_resource_error = 0;
    clean();

    monitor.Address = "http://user:secret@host.test/path";
    result = nm_esp_endpoint_run(&monitor);
    assert(!result.ok && !strcmp(result.status, "Exception"));
    const char *invalid_targets[] = {"https://[::1]junk",   "https://[::1]:abc",
                                     "https://[::1]:65536", "http://host.test:0",
                                     "host.test]",          "host.test:9999999999999999999"};
    for (size_t i = 0; i < sizeof(invalid_targets) / sizeof(*invalid_targets); ++i) {
        result = nm_endpoint_check_nmap(invalid_targets[i], 443, 100);
        assert(!result.ok && !strcmp(result.status, "Exception"));
        clean();
    }
    monitor.Address = "HTTPS://host.test/path";
    result = nm_esp_endpoint_run(&monitor);
    assert(result.ok);
    nm_esp_result_release(&result);
    nmap_test_mode = false;
    clean();
}
static void nmap_tcp_failures(void)
{
    const uint16_t ports[] = {80, 443};
    nm_nmap_scan_request request = {.host = "host.test",
                                    .ports = ports,
                                    .count = 2,
                                    .timeout_ms = 2000,
                                    .no_ping = true,
                                    .show_reason = true};
    connect_resource_error = ENOBUFS;
    nm_nmap_run_result result = nm_nmap_runner_scan(&request);
    assert(result.state == NM_NMAP_RUN_LOCAL_FAILURE);
    nm_nmap_runner_result_release(&result);
    connect_resource_error = 0;
    clean();

    connect_mode = TCP_PENDING;
    socket_option_error = ENOMEM;
    result = nm_nmap_runner_scan(&request);
    assert(result.state == NM_NMAP_RUN_LOCAL_FAILURE);
    nm_nmap_runner_result_release(&result);
    socket_option_error = 0;
    clean();

    connect_mode = TCP_TIMEOUT;
    ipv6_first = true;
    unsigned before = (unsigned)(now_us / 1000);
    result = nm_nmap_runner_scan(&request);
    assert(result.state == NM_NMAP_RUN_COMPLETED);
    assert((unsigned)(now_us / 1000) - before <= 530); /* one budget per port, not per IP */
    assert(strstr(result.standard_output, "filtered") &&
           strstr(result.standard_output, "no-response"));
    nm_nmap_runner_result_release(&result);
    clean();

    atomic_bool cancelled = false;
    request.cancellation = &cancelled;
    cancel_after_wait = &cancelled;
    result = nm_nmap_runner_scan(&request);
    assert(result.state == NM_NMAP_RUN_CANCELLED);
    nm_nmap_runner_result_release(&result);
    cancel_after_wait = NULL;
    request.cancellation = NULL;
    ipv6_first = false;
    connect_mode = TCP_IMMEDIATE;
    clean();

    request.no_ping = false;
    arp_state = NM_ARP_LOCAL_FAILURE;
    result = nm_nmap_runner_scan(&request);
    assert(result.state == NM_NMAP_RUN_LOCAL_FAILURE);
    nm_nmap_runner_result_release(&result);
    clean();
    request.no_ping = true;
    unsigned arp_before = arp_probes;
    result = nm_nmap_runner_scan(&request);
    assert(result.state == NM_NMAP_RUN_COMPLETED && arp_probes == arp_before);
    nm_nmap_runner_result_release(&result);
    clean();
    arp_state = NM_ARP_OFF_LINK;
}
static void nmap_discovery(void)
{
    nm_nmap_discovery_request request = {.display_target = "192.0.2.7/24",
                                         .first_ipv4 = UINT32_C(0xc0000201),
                                         .target_count = NM_NMAP_MAX_TARGETS,
                                         .has_ipv4_range = true,
                                         .timeout_ms = 60000};
    ping_complete = true;
    ping_reply = true;
    nm_nmap_run_result result = nm_nmap_runner_discover(&request);
    assert(result.state == NM_NMAP_RUN_COMPLETED && result.exit_code == 0);
    assert(strstr(result.standard_output, "Host: 192.0.2.1 is up\n"));
    assert(strstr(result.standard_output, "Host: 192.0.2.254 is up\n"));
    assert(strstr(result.standard_output, "Nmap done: 254 IP addresses (254 hosts up) scanned\n"));
    unsigned lines = 0;
    for (const char *p = result.standard_output; *p; ++p)
        lines += *p == '\n';
    assert(lines == 256); /* header + 254 results + summary fit command pagination */
    nm_nmap_runner_result_release(&result);
    clean();

    /* Fully populated ARP reports include every host/MAC and still fit one
     * 256-line command page. ICMP failure must not hide fresh ARP replies. */
    arp_state = NM_ARP_REPLY;
    ping_reply = false;
    request.arp_only = true;
    request.show_reason = true;
    request.verbosity = 1;
    result = nm_nmap_runner_discover(&request);
    assert(result.state == NM_NMAP_RUN_COMPLETED);
    assert(
        strstr(result.standard_output, "Host: 192.0.2.254 is up; MAC Address: 02:03:04:05:06:07"));
    assert(strstr(result.standard_output, "reason=arp-response"));
    assert(strlen(result.standard_output) > 8192 && strlen(result.standard_output) < 32768);
    lines = 0;
    for (const char *p = result.standard_output; *p; ++p)
        lines += *p == '\n';
    assert(lines == 256);
    nm_nmap_runner_result_release(&result);
    clean();
    arp_state = NM_ARP_OFF_LINK;
    result = nm_nmap_runner_discover(&request);
    assert(result.state == NM_NMAP_RUN_ERROR && strstr(result.error, "local IPv4"));
    nm_nmap_runner_result_release(&result);
    clean();
    request.arp_only = request.show_reason = false;
    request.verbosity = 0;
    ping_reply = true;

    request.target_count = 255;
    result = nm_nmap_runner_discover(&request);
    assert(result.state == NM_NMAP_RUN_ERROR);
    nm_nmap_runner_result_release(&result);
    clean();

    atomic_bool cancelled = true;
    request.target_count = 1;
    request.cancellation = &cancelled;
    result = nm_nmap_runner_discover(&request);
    assert(result.state == NM_NMAP_RUN_CANCELLED);
    nm_nmap_runner_result_release(&result);
    clean();

    assert(nm_esp_endpoint_configure_limit(1));
    ping_complete = false;
    nm_esp_result occupied = nm_endpoint_check_icmp("192.0.2.1", 5);
    assert(!occupied.ok && ping_sessions == 1);
    nm_esp_result_release(&occupied);
    request.cancellation = NULL;
    request.timeout_ms = 20;
    result = nm_nmap_runner_discover(&request);
    assert(result.state == NM_NMAP_RUN_LOCAL_FAILURE);
    nm_nmap_runner_result_release(&result);
    finish_ping(0);
    ping_complete = true;
    assert(nm_esp_endpoint_configure_limit(2));
    clean();

    atomic_store(&cancelled, false);
    cancel_after_wait = &cancelled;
    ping_complete = false;
    nm_esp_result cancelled_ping =
        nm_endpoint_check_icmp_cancelable("192.0.2.1", 30000, &cancelled);
    assert(cancelled_ping.disposition == NM_PROBE_LOCAL_FAILURE && ping_sessions == 1);
    assert(strstr(cancelled_ping.message, "cancelled"));
    cancel_after_wait = NULL;
    finish_ping(0); /* cancellation keeps late callbacks alive and safe */
    ping_complete = true;
    clean();
}
static void shared_operation_limits(void)
{
    assert(operation_limit == NM_ENDPOINT_DEFAULT_OPERATIONS);
    assert(!nm_esp_endpoint_configure_limit(0));
    assert(!nm_esp_endpoint_configure_limit(NM_ENDPOINT_MAX_OPERATIONS + 1));
    const unsigned limits[] = {1, 4, 8};
    for (unsigned n = 0; n < sizeof(limits) / sizeof(limits[0]); ++n) {
        unsigned limit = limits[n];
        assert(nm_esp_endpoint_configure_limit(limit));
        dns_complete = ping_complete = false;
        /* Callers time out, but a mixture of DNS and ICMP retains ONE budget. */
        for (unsigned i = 0; i < limit; ++i) {
            if (i % 2)
                (void)nm_endpoint_check_icmp("192.0.2.1", 10);
            else
                (void)nm_endpoint_check_dns("host.test", 10);
            assert(atomic_load(&outstanding_operations) == i + 1);
        }
        assert(!nm_esp_endpoint_configure_limit(limit)); /* must not reset live accounting */
        for (unsigned repeat = 0; repeat < 3; ++repeat) {
            int64_t start = now_us;
            nm_esp_result result = nm_endpoint_check_icmp("192.0.2.1", 10);
            assert(result.disposition == NM_PROBE_LOCAL_FAILURE && now_us - start == 10000);
            result = nm_endpoint_check_dns("host.test", 10);
            assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
            result = nm_endpoint_check_tcp("host.test", 443, 10);
            assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
            struct addrinfo *addresses = NULL;
            assert(!resolve_http("host.test", 443, 10, &addresses));
            assert(!addresses && errno == ENOMEM);
            assert(atomic_load(&outstanding_operations) == limit && semaphores == limit);
        }
        /* A late DNS completion admits an ICMP session (cross-type sharing). */
        on_delay = free_dns_slot;
        ping_complete = true;
        nm_esp_result result = nm_endpoint_check_icmp("192.0.2.1", 100);
        assert(result.ok && atomic_load(&outstanding_operations) == limit - 1);
        for (unsigned i = 0; i < NM_ENDPOINT_MAX_OPERATIONS; ++i) {
            if (pending_dns[i].function)
                finish_dns(i);
            if (pending_ping[i])
                finish_ping(i);
        }
        clean();
        /* Even a single shared slot permits DNS -> ICMP without deadlock. */
        dns_complete = ping_complete = true;
        result = nm_endpoint_check_icmp("host.test", 100);
        assert(result.ok);
        clean();
    }
}

static atomic_uint contenders_ready, contenders_accepted;
static atomic_bool contenders_release;
static void *contend_for_slot(void *unused)
{
    (void)unused;
    bool acquired = nm_endpoint_reserve();
    if (acquired)
        atomic_fetch_add(&contenders_accepted, 1);
    atomic_fetch_add(&contenders_ready, 1);
    while (!atomic_load(&contenders_release))
        sched_yield();
    if (acquired)
        nm_endpoint_release_slot();
    return NULL;
}

static void concurrent_operation_limits(void)
{
    for (unsigned limit = 1; limit <= NM_ENDPOINT_MAX_OPERATIONS; ++limit) {
        assert(nm_esp_endpoint_configure_limit(limit));
        atomic_store(&contenders_ready, 0);
        atomic_store(&contenders_accepted, 0);
        atomic_store(&contenders_release, false);
        pthread_t threads[16];
        for (unsigned i = 0; i < 16; ++i)
            assert(!pthread_create(&threads[i], NULL, contend_for_slot, NULL));
        while (atomic_load(&contenders_ready) < 16)
            sched_yield();
        assert(atomic_load(&contenders_accepted) == limit);
        assert(atomic_load(&outstanding_operations) == limit);
        atomic_store(&contenders_release, true);
        for (unsigned i = 0; i < 16; ++i)
            assert(!pthread_join(threads[i], NULL));
        clean();
    }
}

int main(void)
{
    assert(nm_esp_endpoint_supported("quantum"));
    assert(nm_esp_endpoint_supported("quantumcert"));
    assert(nm_esp_endpoint_supported("nmap"));
    assert(!nm_esp_endpoint_supported("nmapvuln"));
    nm_monitor_record quantum = {
        .Address = "example.com", .EndPointType = "quantum", .Timeout = 15000};
    assert(nm_esp_endpoint_run(&quantum).ok);
    quantum.EndPointType = "quantumcert";
    assert(nm_esp_endpoint_run(&quantum).ok);
    assert(nm_esp_endpoint_supported("blebroadcast"));
    assert(nm_esp_endpoint_supported("blebroadcastlisten"));
    nm_monitor_record ble = {
        .Address = "AA:BB:CC:DD:EE:FF", .EndPointType = "blebroadcast", .Timeout = 75000};
    nm_esp_result ble_result = nm_esp_endpoint_run(&ble);
    assert(ble_result.ok && ble_result.elapsed_ms == 23);
    assert(ble_monitor_seen == &ble && ble_timeout_seen == 75000);
    nm_monitor_record listen = {.EndPointType = "blebroadcastlisten", .Timeout = 25000};
    assert(nm_esp_endpoint_run(&listen).ok);
    assert(ble_monitor_seen == &listen && ble_timeout_seen == 25000);
    shared_operation_limits();
    concurrent_operation_limits();
    assert(nm_esp_endpoint_configure_limit(2));
    lifetimes();
    results();
    strict_numbers();
    nmap_endpoint();
    nmap_tcp_failures();
    nmap_discovery();
    clean();
    puts("endpoint execution/lifetime tests passed (all network operations mocked)");
    return 0;
}
