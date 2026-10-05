#ifndef NM_HTTP_DEADLINE_H
#define NM_HTTP_DEADLINE_H
#include "esp_http_client.h"
#include "esp_transport.h"
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>

/* Resolver transfers an owned addrinfo list on success. It must bound its wait
 * and keep any late DNS callback's lifetime independent of this request. */
typedef bool (*nm_http_resolver)(const char *, unsigned, unsigned, struct addrinfo **);
typedef struct nm_http_deadline nm_http_deadline;
nm_http_deadline *nm_http_deadline_new(unsigned timeout_ms, nm_http_resolver resolver);
esp_transport_handle_t nm_http_deadline_transport(nm_http_deadline *);
/* Configure before connecting. HTTPS probe policy uses midnight UTC + 7 days;
 * default off for ordinary HTTP and other users of this transport. */
void nm_http_deadline_check_certificate_expiry(nm_http_deadline *, bool enabled);
void nm_http_deadline_bind(nm_http_deadline *, esp_http_client_handle_t);
bool nm_http_deadline_expired(nm_http_deadline *);
/* Sticky local resource failure captured before an underlying transport closes. */
bool nm_http_deadline_resource_failed(const nm_http_deadline *);
/* Call AFTER HTTP client cleanup; the client borrows the custom transport. */
void nm_http_deadline_free(nm_http_deadline *);
#endif
