#include "processor_internal.h"
#include "cmd_processor_catalog.h"
#include "cmd_processor_message.h"
#include "message_publish.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include <stdio.h>
#include <strings.h>

struct nm_cmd_job {
    yyjson_mut_doc *response; /* Owner task only; never accessed by worker. */
    nm_embedded_command request;
    nm_cmd_result result; /* Worker writes before done release; owner reads after acquire. */
    atomic_bool cancellation, done;
    TaskHandle_t task;
    bool formatted, ack_sent;
};
static const char *TAG = "nm_cmd_processor";

static bool available_type(const processor *agent, nm_cmd_kind kind)
{
    yyjson_mut_val *settings = yyjson_mut_doc_get_root(agent->config->doc);
    yyjson_mut_val *disabled = yyjson_mut_obj_get(settings, "DisabledCommands"), *item;
    size_t i, n;
    yyjson_mut_arr_foreach(disabled, i, n, item)
    {
        const char *name = yyjson_mut_get_str(item);
        if (name && (!strcasecmp(name, nm_cmd_kind_type(kind)) ||
                     !strcasecmp(name, nm_cmd_kind_name(kind))))
            return false;
    }
    return true;
}

static bool publish(processor *agent, yyjson_mut_doc *doc, bool ack)
{
    return nm_esp_publish_event(
        agent->config, agent->client, ack ? "processor/out/scan-ack" : "processor/out/scan-ran",
        yyjson_mut_doc_get_root(doc), NM_MESSAGE_JSON, "ProcessorScanDataObj");
}

static bool prepare_ack(yyjson_mut_doc *doc)
{
    const char *id = string_field(yyjson_mut_doc_get_root(doc), "MessageID");
    char output[192];
    int n = snprintf(output, sizeof(output), "Acknowledged command with MessageID %s", id);
    return n > 0 && (size_t)n < sizeof(output) && nm_cmd_message_output(doc, output, true, true);
}

static void worker(void *argument)
{
    struct nm_cmd_job *job = argument;
    job->result = nm_cmd_kind_run(&job->request, &job->cancellation);
    atomic_store_explicit(&job->done, true, memory_order_release);
    /* Owner deletes the WithCaps task only after completion, never mid-I/O. */
    for (;;)
        vTaskSuspend(NULL);
}

static void release(struct nm_cmd_job *job)
{
    if (job->task)
        vTaskDeleteWithCaps(job->task);
    yyjson_mut_doc_free(job->response);
    free(job->result.output);
    free(job);
}

void nm_processor_cmd_poll(processor *agent)
{
    struct nm_cmd_job *job = agent->cmd_job;
    if (!job || !agent->connected || agent->updating)
        return;
    if (!job->ack_sent) {
        /* The ack is constructed once at submission. Retrying publication
         * must not grow the mutable document's arena during a broker outage. */
        job->ack_sent = publish(agent, job->response, true);
        if (!job->ack_sent)
            return;
    }
    if (!atomic_load_explicit(&job->done, memory_order_acquire))
        return;
    if (job->task) {
        vTaskDeleteWithCaps(job->task);
        job->task = NULL;
    }
    if (!job->formatted) {
        yyjson_mut_val *settings = yyjson_mut_doc_get_root(agent->config->doc);
        yyjson_mut_val *limit = yyjson_mut_obj_get(settings, "CmdReturnDataLineLimit");
        unsigned default_limit = yyjson_mut_is_uint(limit) && yyjson_mut_get_uint(limit) > 0 &&
                                         yyjson_mut_get_uint(limit) <= 10000
                                     ? (unsigned)yyjson_mut_get_uint(limit)
                                     : 100;
        yyjson_mut_doc *formatted = nm_json_clone(yyjson_mut_doc_get_root(job->response));
        job->formatted =
            formatted && nm_cmd_message_format(formatted,
                                               job->result.output
                                                   ? job->result.output
                                                   : "Command failed: local allocation unavailable",
                                               job->result.success, default_limit);
        if (!job->formatted) {
            yyjson_mut_doc_free(formatted);
            return;
        }
        yyjson_mut_doc_free(job->response);
        job->response = formatted;
    }
    yyjson_mut_val *root = yyjson_mut_doc_get_root(job->response);
    yyjson_mut_val *send = yyjson_mut_obj_get(root, "SendMessage");
    if ((!send || !yyjson_mut_is_false(send)) && !publish(agent, job->response, false))
        return;
    const char *id = string_field(root, "MessageID");
    memcpy(agent->last_cmd_id, id, strlen(id) + 1);
    ESP_LOGI(TAG, "%s completed MessageID=%s success=%d", nm_cmd_kind_type(job->request.kind), id,
             job->result.success);
    agent->cmd_job = NULL;
    release(job);
}

bool nm_processor_cmd_dispatch(processor *agent, const char *operation, yyjson_mut_val *data)
{
    const char *id = string_field(data, "MessageID"), *type = string_field(data, "Type");
    const char *target = string_field(data, "AgentID");
    if (!id || !*id || strlen(id) > 128 ||
        (target && *target && strcmp(target, agent->config->app_id)))
        return false;
    bool list = !strcmp(operation, "getCmdProcessorList");
    nm_cmd_kind kind = NM_CMD_CERT;
    if (!list && (!type || !*type || strlen(type) > 128))
        return false;
    yyjson_mut_doc *response = nm_json_clone(data);
    if (!response)
        return false;
    bool result = false;
    if (!list && !nm_cmd_kind_find(type, &kind)) {
        char output[384];
        int count = snprintf(
            output, sizeof(output),
            "Error : %s cmd processor not available for this agent. Try calling the "
            "get_cmd_processor_list function to get a list of cmd processors that are available..",
            type);
        result = count > 0 && (size_t)count < sizeof(output) &&
                 nm_cmd_message_output(response, output, false, false) &&
                 publish(agent, response, false);
        goto done;
    }
    if (!prepare_ack(response))
        goto done;
    bool ack = publish(agent, response, true);
    if (!strcmp(operation, "cancelCommand")) {
        struct nm_cmd_job *job = agent->cmd_job;
        const char *running =
            job ? string_field(yyjson_mut_doc_get_root(job->response), "MessageID") : NULL;
        if (running && !strcmp(running, id) && job->request.kind == kind) {
            atomic_store(&job->cancellation, true);
            result = true;
        }
    } else if (list || !strcmp(operation, "getCmdProcessorHelp")) {
        char catalog[512] =
            "Success: got the list of cmd processor types for the agent. cmd_processor_types : [";
        size_t used = strlen(catalog);
        bool comma = false;
        for (unsigned i = 0; i < NM_CMD_COUNT; ++i) {
            if (!available_type(agent, (nm_cmd_kind)i))
                continue;
            int count = snprintf(catalog + used, sizeof(catalog) - used, "%s'%s'",
                                 comma ? ", " : "", nm_cmd_kind_type((nm_cmd_kind)i));
            if (count < 0 || (size_t)count + 2 >= sizeof(catalog) - used)
                goto done;
            used += (size_t)count;
            comma = true;
        }
        catalog[used++] = ']';
        catalog[used] = 0;
        const char *output = list ? catalog
                             : available_type(agent, kind)
                                 ? nm_cmd_kind_help(kind)
                                 : "Command processor is disabled on this device";
        result =
            nm_cmd_message_output(response, output, list || available_type(agent, kind), false) &&
            publish(agent, response, false);
    } else if (!strcmp(operation, "processorCommand")) {
        const char *arguments = string_field(data, "Arguments"), *error = NULL;
        if (!strcmp(agent->last_cmd_id, id))
            result = ack;
        else if (agent->cmd_job) {
            const char *running =
                string_field(yyjson_mut_doc_get_root(agent->cmd_job->response), "MessageID");
            if (!strcmp(running, id))
                result = ack;
            else
                result = nm_cmd_message_output(response, "Embedded command worker is busy", false,
                                               false) &&
                         publish(agent, response, false);
        } else if (!available_type(agent, kind)) {
            result = nm_cmd_message_output(response, "Command processor is disabled on this device",
                                           false, false) &&
                     publish(agent, response, false);
        } else {
            yyjson_mut_val *timeout = yyjson_mut_obj_get(data, "TimeoutSeconds");
            unsigned seconds = 600;
            if (timeout) {
                if (!yyjson_mut_is_uint(timeout) || yyjson_mut_get_uint(timeout) > 2147483 ||
                    !yyjson_mut_get_uint(timeout)) {
                    result = nm_cmd_message_output(response,
                                                   "Invalid TimeoutSeconds: expected positive "
                                                   "int32 seconds within the millisecond budget",
                                                   false, false) &&
                             publish(agent, response, false);
                    goto done;
                }
                seconds = (unsigned)yyjson_mut_get_uint(timeout);
            }
            /* Reject invalid pagination before running or retaining a job. */
            yyjson_mut_doc *check = nm_json_clone(data);
            bool valid = check && nm_cmd_message_format(check, "check", true, 100);
            yyjson_mut_doc_free(check);
            if (!valid) {
                result = nm_cmd_message_output(response,
                                               "Invalid command pagination: LineLimit must be -1, "
                                               "-2 or positive; Page must be an int32",
                                               false, false) &&
                         publish(agent, response, false);
                goto done;
            }
            struct nm_cmd_job *job = nm_bulk_calloc(1, sizeof(*job));
            if (!job) {
                result =
                    nm_cmd_message_output(response, "Command failed: local allocation unavailable",
                                          false, false) &&
                    publish(agent, response, false);
                goto done;
            }
            if (!nm_cmd_kind_parse(kind, arguments, seconds * 1000, &job->request, &error)) {
                free(job);
                result = nm_cmd_message_output(
                             response, error ? error : "Invalid command arguments", false, false) &&
                         publish(agent, response, false);
                goto done;
            }
            job->response = response;
            job->ack_sent = ack;
            atomic_init(&job->cancellation, false);
            atomic_init(&job->done, false);
            if (xTaskCreatePinnedToCoreWithCaps(worker, "nm_command", 16384, job, tskIDLE_PRIORITY,
                                                &job->task, 1,
                                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
                job->response = NULL;
                release(job);
                result = nm_cmd_message_output(response, "Command failed: worker unavailable",
                                               false, false) &&
                         publish(agent, response, false);
            } else {
                agent->cmd_job = job;
                response = NULL;
                ESP_LOGI(TAG, "%s started MessageID=%s", nm_cmd_kind_type(kind), id);
                result = true;
            }
        }
    }
done:
    yyjson_mut_doc_free(response);
    return result;
}
