/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_map.h>

#include <cfl/cfl.h>

#define PROMOTE_STATIC_METRICS_ON_LABEL_INSERT

struct internal_processor_context {
    struct mk_list *update_list;
    struct mk_list *insert_list;
    struct mk_list *upsert_list;
    struct mk_list *delete_list;
    struct mk_list *hash_list;

    /* internal labels ready to append */
    struct cfl_list update_labels;
    struct cfl_list insert_labels;
    struct cfl_list upsert_labels;
    struct mk_list  delete_labels;
    struct mk_list  hash_labels;

    struct flb_processor_instance *instance;
    struct flb_config *config;
};

/*
 * LOCAL
 */
static int hex_encode(unsigned char *input_buffer,
                      size_t input_length,
                      cfl_sds_t *output_buffer)
{
    const char hex[] = "0123456789abcdef";
    cfl_sds_t  result;
    size_t     index;

    if (cfl_sds_alloc(*output_buffer) <= (input_length * 2)) {
        result = cfl_sds_increase(*output_buffer,
                                  (input_length * 2) -
                                  cfl_sds_alloc(*output_buffer));

        if (result == NULL) {
            return FLB_FALSE;
        }

        *output_buffer = result;
    }

    for (index = 0; index < input_length; index++) {
        (*output_buffer)[index * 2 + 0] = hex[(input_buffer[index] >> 4) & 0xF];
        (*output_buffer)[index * 2 + 1] = hex[(input_buffer[index] >> 0) & 0xF];
    }

    cfl_sds_set_len(*output_buffer, input_length * 2);

    (*output_buffer)[index * 2] = '\0';

    return FLB_TRUE;
}

static int process_label_modification_list_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct mk_list *destination_list)
{
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    int                        result;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        result = flb_slist_add(destination_list, source_entry->val.str);

        if (result != 0) {
            flb_plg_error(plugin_instance,
                          "could not append label name %s\n",
                          source_entry->val.str);

            return -1;
        }
    }

    return 0;
}

static int process_label_modification_kvlist_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct cfl_list *destination_list)
{
    struct cfl_kv             *processed_pair;
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    struct flb_slist_entry    *value;
    struct flb_slist_entry    *key;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        if (mk_list_size(source_entry->val.list) != 2) {
            flb_plg_error(plugin_instance,
                          "'%s' expects a key and a value, "
                          "e.g: '%s version 1.8.0'",
                          setting_name, setting_name);

            return -1;
        }

        key = mk_list_entry_first(source_entry->val.list,
                                  struct flb_slist_entry, _head);

        value = mk_list_entry_last(source_entry->val.list,
                                   struct flb_slist_entry, _head);

        processed_pair = cfl_kv_item_create(destination_list,
                                            key->str,
                                            value->str);

        if (processed_pair == NULL) {
            flb_plg_error(plugin_instance,
                          "could not append label %s=%s\n",
                          key->str,
                          value->str);

            return -1;
        }
    }

    return 0;
}

static void destroy_context(struct internal_processor_context *context)
{
    if (context != NULL) {
        cfl_kv_release(&context->update_labels);
        cfl_kv_release(&context->insert_labels);
        cfl_kv_release(&context->upsert_labels);
        flb_slist_destroy(&context->delete_labels);
        flb_slist_destroy(&context->hash_labels);

        flb_free(context);
    }
}

static struct internal_processor_context *
        create_context(struct flb_processor_instance *processor_instance,
                       struct flb_config *config)
{
    struct internal_processor_context *context;
    int                                result;

    context = flb_calloc(1, sizeof(struct internal_processor_context));

    if (context != NULL) {
        context->instance = processor_instance;
        context->config = config;

        cfl_kv_init(&context->update_labels);
        cfl_kv_init(&context->insert_labels);
        cfl_kv_init(&context->upsert_labels);
        flb_slist_create(&context->delete_labels);
        flb_slist_create(&context->hash_labels);

        result = flb_processor_instance_config_map_set(processor_instance, (void *) context);

        if (result == 0) {
            result = process_label_modification_kvlist_setting(processor_instance,
                                                               "update",
                                                               context->update_list,
                                                               &context->update_labels);
        }

        if (result == 0) {
            result = process_label_modification_kvlist_setting(processor_instance,
                                                               "insert",
                                                               context->insert_list,
                                                               &context->insert_labels);
        }

        if (result == 0) {
            result = process_label_modification_kvlist_setting(processor_instance,
                                                               "upsert",
                                                               context->upsert_list,
                                                               &context->upsert_labels);
        }

        if (result == 0) {
            result = process_label_modification_list_setting(processor_instance,
                                                             "delete",
                                                             context->delete_list,
                                                             &context->delete_labels);
        }

        if (result == 0) {
            result = process_label_modification_list_setting(processor_instance,
                                                             "hash",
                                                             context->hash_list,
                                                             &context->hash_labels);
        }

        if (result != 0) {
            destroy_context(context);

            context = NULL;
        }
    }
    else {
        flb_errno();
    }

    return context;
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    processor_instance->context = (void *) create_context(
                                            processor_instance, config);

    if (processor_instance->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}


static int cb_exit(struct flb_processor_instance *processor_instance)
{
    if (processor_instance != NULL &&
        processor_instance->context != NULL) {
        destroy_context(processor_instance->context);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int metrics_context_insert_static_label(struct cmt *metrics_context,
                                               char *label_name,
                                               char *label_value)
{
    if (cmt_label_add(metrics_context, label_name, label_value) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int metrics_context_upsert_static_label(struct cmt *metrics_context,
                                               char *label_name,
                                               char *label_value)
{
    int result;

    result = cmt_contains_static_label(metrics_context,
                                       label_name);

    if (result == FLB_TRUE) {
        return cmt_update_static_label(metrics_context,
                                       label_name,
                                       label_value);
    }

    return metrics_context_insert_static_label(metrics_context,
                                               label_name,
                                               label_value);
}

static int update_labels(struct cmt *metrics_context,
                         struct cfl_list *labels)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, labels) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = cmt_contains_dynamic_label(metrics_context,
                                                        pair->key);

        if (result == FLB_TRUE) {
            result = cmt_update_dynamic_label(metrics_context,
                                              pair->key,
                                              pair->val);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }

        result = cmt_contains_static_label(metrics_context,
                                                       pair->key);

        if (result == FLB_TRUE) {
            result = cmt_update_static_label(metrics_context,
                                                         pair->key,
                                                         pair->val);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int insert_labels(struct cmt *metrics_context,
                         struct cfl_list *labels)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, labels) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = cmt_contains_dynamic_label(metrics_context,
                                                        pair->key);

        if (result == FLB_TRUE) {
            result = cmt_insert_dynamic_label(metrics_context,
                                                          pair->key,
                                                          pair->val);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
        else {
            result = cmt_contains_static_label(metrics_context,
                                                           pair->key);

            if (result == FLB_FALSE) {
                result = metrics_context_insert_static_label(metrics_context,
                                                             pair->key,
                                                             pair->val);

                if (result == FLB_FALSE) {
                    return FLB_FALSE;
                }
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int upsert_labels(struct cmt *metrics_context,
                         struct cfl_list *labels)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, labels) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = cmt_contains_dynamic_label(metrics_context,
                                                        pair->key);

        if (result == FLB_TRUE) {
            result = cmt_upsert_dynamic_label(metrics_context,
                                              pair->key,
                                              pair->val);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
        else {
            result = metrics_context_upsert_static_label(metrics_context,
                                                         pair->key,
                                                         pair->val);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int delete_labels(struct cmt *metrics_context,
                         struct mk_list *labels)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, labels) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = cmt_contains_dynamic_label(metrics_context,
                                                        entry->str);

        if (result == FLB_TRUE) {
            result = cmt_remove_dynamic_label(metrics_context,
                                              entry->str);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
        else {
            result = cmt_contains_static_label(metrics_context,
                                                           entry->str);

            if (result == FLB_TRUE) {
                result = cmt_remove_static_label(metrics_context,
                                                             entry->str);

                if (result == FLB_FALSE) {
                    return FLB_FALSE;
                }
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int hash_transformer(struct cmt_metric *metric, cfl_sds_t *value)
{
    unsigned char digest_buffer[32];
    int           result;

    if (value == NULL) {
        return FLB_FALSE;
    }

    if (cfl_sds_len(*value) == 0) {
        return FLB_TRUE;
    }

    result = flb_hash_simple(FLB_HASH_SHA256,
                             (unsigned char *) *value,
                             cfl_sds_len(*value),
                             digest_buffer,
                             sizeof(digest_buffer));

    if (result != FLB_CRYPTO_SUCCESS) {
        return FLB_FALSE;
    }

    return hex_encode(digest_buffer, sizeof(digest_buffer), value);
}

static int hash_labels(struct cmt *metrics_context,
                       struct mk_list *labels)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, labels) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = cmt_contains_dynamic_label(metrics_context,
                                                        entry->str);

        if (result == FLB_TRUE) {
            result = cmt_transform_dynamic_label(metrics_context,
                                                 entry->str,
                                                 hash_transformer);

            if (result == FLB_FALSE) {
                return FLB_FALSE;
            }
        }
        else {
            result = cmt_contains_static_label(metrics_context,
                                                           entry->str);

            if (result == FLB_TRUE) {
                result = cmt_transform_static_label(metrics_context,
                                                                entry->str,
                                                                hash_transformer);

                if (result == FLB_FALSE) {
                    return FLB_FALSE;
                }
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_metrics(struct flb_processor_instance *processor_instance,
                              struct cmt *metrics_context,
                              const char *tag,
                              int tag_len)
{
    struct internal_processor_context *processor_context;
    int                                result;

    processor_context =
        (struct internal_processor_context *) processor_instance->context;

    result = delete_labels(metrics_context,
                           &processor_context->delete_labels);

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = update_labels(metrics_context,
                               &processor_context->update_labels);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = upsert_labels(metrics_context,
                               &processor_context->upsert_labels);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = insert_labels(metrics_context,
                               &processor_context->insert_labels);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = hash_labels(metrics_context,
                             &processor_context->hash_labels);
    }

    if (result != FLB_PROCESSOR_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_SLIST_1, "update", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                update_list),
        "Updates a label. Usage : 'update label_name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "insert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                insert_list),
        "Inserts a label. Usage : 'insert label_name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "upsert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                upsert_list),
        "Inserts or updates a label. Usage : 'upsert label_name value'"
    },
    {
        FLB_CONFIG_MAP_STR, "delete", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                delete_list),
        "Deletes a label. Usage : 'delete label_name'"
    },
    {
        FLB_CONFIG_MAP_STR, "hash", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                hash_list),
        "Replaces a labels value with its SHA1 hash. Usage : 'hash label_name'"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_labels_plugin = {
    .name               = "labels",
    .description        = "Modifies metrics labels",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
