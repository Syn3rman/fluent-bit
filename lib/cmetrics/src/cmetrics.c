/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <stdlib.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_label.h>
#include <cmetrics/cmt_version.h>
#include <cmetrics/cmt_map.h>

#include <cfl/cfl_kvlist.h>

void cmt_initialize()
{
    cmt_atomic_initialize();
}

struct cmt *cmt_create()
{
    struct cmt *cmt;

    cmt = calloc(1, sizeof(struct cmt));
    if (!cmt) {
        cmt_errno();
        return NULL;
    }

    cmt->static_labels = cmt_labels_create();
    if (!cmt->static_labels) {
        free(cmt);
        return NULL;
    }

    cmt->internal_metadata = cfl_kvlist_create();

    if (cmt->internal_metadata == NULL) {
        cmt_labels_destroy(cmt->static_labels);

        free(cmt);
        return NULL;
    }

    cmt->external_metadata = cfl_kvlist_create();

    if (cmt->external_metadata == NULL) {
        cfl_kvlist_destroy(cmt->internal_metadata);
        cmt_labels_destroy(cmt->static_labels);

        free(cmt);
        return NULL;
    }

    cfl_list_init(&cmt->counters);
    cfl_list_init(&cmt->gauges);
    cfl_list_init(&cmt->histograms);
    cfl_list_init(&cmt->summaries);
    cfl_list_init(&cmt->untypeds);

    cmt->log_level = CMT_LOG_ERROR;

    cfl_list_entry_init(&cmt->_head);

    return cmt;
}

void cmt_destroy(struct cmt *cmt)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_summary *s;
    struct cmt_histogram *h;
    struct cmt_untyped *u;

    cfl_list_foreach_safe(head, tmp, &cmt->counters) {
        c = cfl_list_entry(head, struct cmt_counter, _head);
        cmt_counter_destroy(c);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->gauges) {
        g = cfl_list_entry(head, struct cmt_gauge, _head);
        cmt_gauge_destroy(g);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->summaries) {
        s = cfl_list_entry(head, struct cmt_summary, _head);
        cmt_summary_destroy(s);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->histograms) {
        h = cfl_list_entry(head, struct cmt_histogram, _head);
        cmt_histogram_destroy(h);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->untypeds) {
        u = cfl_list_entry(head, struct cmt_untyped, _head);
        cmt_untyped_destroy(u);
    }

    if (cmt->static_labels) {
        cmt_labels_destroy(cmt->static_labels);
    }

    if (cmt->internal_metadata != NULL) {
        cfl_kvlist_destroy(cmt->internal_metadata);
    }

    if (cmt->external_metadata != NULL) {
        cfl_kvlist_destroy(cmt->external_metadata);
    }

    free(cmt);
}

int cmt_label_add(struct cmt *cmt, char *key, char *val)
{
    return cmt_labels_add_kv(cmt->static_labels, key, val);
}

char *cmt_version()
{
    return CMT_VERSION_STR;
}

int cmt_contains_static_label(struct cmt *metrics_context,
                              char *label_name)
{
    struct cfl_list  *label_iterator;
    struct cmt_label *label;

    cfl_list_foreach(label_iterator, &metrics_context->static_labels->list) {
        label = cfl_list_entry(label_iterator,
                               struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

int cmt_insert_static_label(struct cmt *metrics_context,
                            char *label_name,
                            char *label_value)
{
    if (cmt_label_add(metrics_context, label_name, label_value) != 0) {
        return CMT_FALSE;
    }

    return CMT_TRUE;
}

int cmt_update_static_label(struct cmt *metrics_context,
                            char *label_name,
                            char *label_value)
{
    struct cfl_list  *iterator;
    cfl_sds_t         result;
    struct cmt_label *label;

    cfl_list_foreach(iterator, &metrics_context->static_labels->list) {
        label = cfl_list_entry(iterator,
                               struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            cfl_sds_set_len(label->val, 0);

            result = cfl_sds_cat(label->val, label_value, strlen(label_value));

            if (result == NULL) {
                return CMT_FALSE;
            }

            label->val = result;

            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

int cmt_transform_static_label(struct cmt *metrics_context,
                               char *label_name,
                               cmt_metric_transformer transformer)
{
    struct cfl_list  *iterator;
    struct cmt_label *label;

    cfl_list_foreach(iterator, &metrics_context->static_labels->list) {
        label = cfl_list_entry(iterator,
                               struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            return transformer(NULL, &label->val);
        }
    }

    return CMT_FALSE;
}

int cmt_upsert_static_label(struct cmt *metrics_context,
                            char *label_name,
                            char *label_value)
{
    int result;

    result = cmt_contains_static_label(metrics_context,
                                       label_name);

    if (result == CMT_TRUE) {
        return cmt_update_static_label(metrics_context,
                                       label_name,
                                       label_value);
    }

    return cmt_insert_static_label(metrics_context,
                                   label_name,
                                   label_value);
}

int cmt_remove_static_label(struct cmt *metrics_context,
                            char *label_name)
{
    struct cfl_list  *iterator;
    struct cmt_label *label;

    cfl_list_foreach(iterator,
                     &metrics_context->static_labels->list) {
        label = cfl_list_entry(iterator, struct cmt_label, _head);

        if (strcasecmp(label_name, label->key) == 0) {
            cmt_label_destroy(label);

            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

int cmt_contains_dynamic_label(struct cmt *metrics_context,
                               char *label_name)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        if(cmt_map_contains_label(histogram->map, label_name) == CMT_TRUE) {
            return CMT_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        if(cmt_map_contains_label(summary->map, label_name) == CMT_TRUE) {
            return CMT_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        if(cmt_map_contains_label(untyped->map, label_name) == CMT_TRUE) {
            return CMT_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        if(cmt_map_contains_label(counter->map, label_name) == CMT_TRUE) {
            return CMT_TRUE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        if(cmt_map_contains_label(gauge->map, label_name) == CMT_TRUE) {
            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

int cmt_insert_dynamic_label(struct cmt *metrics_context,
                             char *label_name,
                             char *label_value)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = cmt_map_insert_label(histogram->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = cmt_map_insert_label(summary->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = cmt_map_insert_label(untyped->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = cmt_map_insert_label(counter->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = cmt_map_insert_label(gauge->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}

int cmt_update_dynamic_label(struct cmt *metrics_context,
                             char *label_name,
                             char *label_value)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = cmt_map_update_label(histogram->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = cmt_map_update_label(summary->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = cmt_map_update_label(untyped->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = cmt_map_update_label(counter->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = cmt_map_update_label(gauge->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}

int cmt_update_transform_dynamic_label(struct cmt *metrics_context,
                                       char *label_name,
                                       cmt_metric_transformer transformer)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = cmt_map_transform_label(histogram->map,
                                         label_name,
                                         transformer);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = cmt_map_transform_label(summary->map,
                                         label_name,
                                         transformer);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = cmt_map_transform_label(untyped->map,
                                         label_name,
                                         transformer);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = cmt_map_transform_label(counter->map,
                                         label_name,
                                         transformer);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = cmt_map_transform_label(gauge->map,
                                         label_name,
                                         transformer);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}

int cmt_update_upsert_dynamic_label(struct cmt *metrics_context,
                                    char *label_name,
                                    char *label_value)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = cmt_map_upsert_label(histogram->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = cmt_map_upsert_label(summary->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = cmt_map_upsert_label(untyped->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = cmt_map_upsert_label(counter->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = cmt_map_upsert_label(gauge->map,
                                      label_name,
                                      label_value);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}

int cmt_update_remove_dynamic_label(struct cmt *metrics_context,
                                    char *label_name)
{
    struct cfl_list      *metric_iterator;
    struct cmt_histogram *histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    int                   result;
    struct cmt_gauge     *gauge;

    cfl_list_foreach(metric_iterator, &metrics_context->histograms) {
        histogram = cfl_list_entry(metric_iterator, struct cmt_histogram, _head);

        result = cmt_map_remove_label(histogram->map,
                                      label_name);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->summaries) {
        summary = cfl_list_entry(metric_iterator, struct cmt_summary, _head);

        result = cmt_map_remove_label(summary->map,
                                      label_name);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->untypeds) {
        untyped = cfl_list_entry(metric_iterator, struct cmt_untyped, _head);

        result = cmt_map_remove_label(untyped->map,
                                      label_name);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->counters) {
        counter = cfl_list_entry(metric_iterator, struct cmt_counter, _head);

        result = cmt_map_remove_label(counter->map,
                                      label_name);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    cfl_list_foreach(metric_iterator, &metrics_context->gauges) {
        gauge = cfl_list_entry(metric_iterator, struct cmt_gauge, _head);

        result = cmt_map_remove_label(gauge->map,
                                      label_name);

        if (result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}