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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>

/*
 * This interface file provide helper functions to compose a dynamic list
 * of custom labels with specific keys and values. Note that this is not
 * about labels defined by metrics upon creation, but label lists to be
 * used by the encoders when formatting the data.
 */
struct cmt_labels *cmt_labels_create()
{
    struct cmt_labels *l;

    l = malloc(sizeof(struct cmt_labels));
    if (!l) {
        cmt_errno();
        return NULL;
    }
    cfl_list_init(&l->list);
    return l;
}

void cmt_labels_destroy(struct cmt_labels *labels)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_label *l;

    cfl_list_foreach_safe(head, tmp, &labels->list) {
        l = cfl_list_entry(head, struct cmt_label, _head);
        if (l->key) {
            cfl_sds_destroy(l->key);
        }
        if (l->val) {
            cfl_sds_destroy(l->val);
        }
        cfl_list_del(&l->_head);
        free(l);
    }

    free(labels);
}

int cmt_labels_add_kv(struct cmt_labels *labels, char *key, char *val)
{
    struct cmt_label *l;

    l = malloc(sizeof(struct cmt_label));
    if (!l) {
        cmt_errno();
        return -1;
    }

    l->key = cfl_sds_create(key);
    if (!l->key) {
        free(l);
        return -1;
    }

    l->val = cfl_sds_create(val);
    if (!l->val) {
        cfl_sds_destroy(l->key);
        free(l);
        return -1;
    }

    cfl_list_add(&l->_head, &labels->list);
    return 0;
}

int cmt_labels_count(struct cmt_labels *labels)
{
    int c = 0;
    struct cfl_list *head;

    cfl_list_foreach(head, &labels->list) {
        c++;
    }

    return c;
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

void cmt_label_destroy(struct cmt_label *label)
{
    if (label != NULL) {
        if (!cfl_list_entry_is_orphan(&label->_head)) {
            cfl_list_del(&label->_head);
        }

        if (label->key != NULL) {
            cfl_sds_destroy(label->key);
        }

        if (label->val != NULL) {
            cfl_sds_destroy(label->val);
        }

        free(label);
    }
}

int cmt_transform_static_label(struct cmt *metrics_context,
                               char *label_name,
                               label_transformer transformer)
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

int cmt_data_point_remove_label_value(struct cmt_metric *metric,
                                      size_t label_index)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    size_t                index;

    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            cmt_map_label_destroy(label);

            return CMT_TRUE;
        }

        index++;
    }

    return CMT_FALSE;
}

int cmt_data_point_transform_label_value(struct cmt_metric *metric,
                                         size_t label_index,
                                         label_transformer transformer)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    size_t                index;

    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            return transformer(metric, &label->name);
        }

        index++;
    }

    return CMT_FALSE;
}

int cmt_data_point_set_label_value(struct cmt_metric *metric,
                                   size_t label_index,
                                   char *label_value,
                                   int overwrite,
                                   int insert)
{
    struct cmt_map_label *new_label;
    struct cfl_list      *iterator;
    cfl_sds_t             result;
    size_t                index;
    struct cmt_map_label *label;

    label = NULL;
    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            break;
        }

        index++;
    }

    if (label_index != index) {
        return CMT_FALSE;
    }

    if (insert == CMT_TRUE) {
        new_label = cmt_map_label_create(label_value);

        if (new_label == NULL) {
            return CMT_FALSE;
        }

        if (label != NULL) {
            cfl_list_add_after(&new_label->_head,
                               &label->_head,
                               &metric->labels);
        }
        else {
            cfl_list_append(&new_label->_head,
                            &metric->labels);
        }
    }
    else {
        if (label == NULL) {
            return CMT_FALSE;
        }

        if (label->name == NULL) {
            label->name = cfl_sds_create(label_value);

            if (label->name == NULL) {
                return CMT_FALSE;
            }
        }
        else {
            if (overwrite == CMT_TRUE ||
                cfl_sds_len(label->name) == 0) {
                cfl_sds_set_len(label->name, 0);

                result = cfl_sds_cat(label->name,
                                     label_value,
                                     strlen(label_value));

                if (result == NULL) {
                    return CMT_FALSE;
                }

                label->name = result;
            }
        }
    }

    return CMT_TRUE;
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

int cmt_transform_dynamic_label(struct cmt *metrics_context,
                                char *label_name,
                                label_transformer transformer)
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

int cmt_upsert_dynamic_label(struct cmt *metrics_context,
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

int cmt_remove_dynamic_label(struct cmt *metrics_context,
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
