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
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_map.h>

static inline int metric_exchange(struct cmt_metric *metric, uint64_t timestamp,
                                  double new_value, double old_value)
{
    uint64_t tmp_new;
    uint64_t tmp_old;
    int      result;

    tmp_new = cmt_math_d64_to_uint64(new_value);
    tmp_old = cmt_math_d64_to_uint64(old_value);

    result = cmt_atomic_compare_exchange(&metric->val, tmp_old, tmp_new);

    if(0 == result) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);

    return 1;
}

static inline void add(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    double   old;
    double   new;
    int      result;

    do {
        old = cmt_metric_get_value(metric);
        new = old + val;

        result = metric_exchange(metric, timestamp, new, old);
    }
    while(0 == result);
}

void cmt_metric_set(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64(val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->timestamp, timestamp);
}

static inline int metric_hist_exchange(struct cmt_metric *metric,
                                       uint64_t timestamp,
                                       int bucket_id,
                                       uint64_t new, uint64_t old)
{
    int result;

    result = cmt_atomic_compare_exchange(&metric->hist_buckets[bucket_id],
                                         old, new);
    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

void cmt_metric_hist_bucket_inc(struct cmt_metric *metric, uint64_t timestamp,
                                int bucket_id)
{
    int result;
    uint64_t old;
    uint64_t new;

    do {
        old = cmt_atomic_load(&metric->hist_buckets[bucket_id]);
        new = old + 1;
        result = metric_hist_exchange(metric, timestamp, bucket_id, new, old);
    }
    while (result == 0);
}


void cmt_metric_inc(struct cmt_metric *metric, uint64_t timestamp)
{
    add(metric, timestamp, 1);
}

void cmt_metric_dec(struct cmt_metric *metric, uint64_t timestamp)
{
    double volatile val = 1.0;

    add(metric, timestamp, val * -1);
}

void cmt_metric_add(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    add(metric, timestamp, val);
}

void cmt_metric_sub(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    add(metric, timestamp, (double volatile) val * -1);
}

double cmt_metric_get_value(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->val);

    return cmt_math_uint64_to_d64(val);
}

uint64_t cmt_metric_get_timestamp(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->timestamp);

    return val;
}

struct cmt_metric *cmt_metric_create_map(uint64_t hash,
                                         int labels_count, char **labels_val)
{
    int i;
    char *name;
    struct cmt_metric *metric;
    struct cmt_map_label *label;

    metric = calloc(1, sizeof(struct cmt_metric));
    if (!metric) {
        cmt_errno();
        return NULL;
    }
    cfl_list_init(&metric->labels);
    metric->val = 0.0;
    metric->hash = hash;

    for (i = 0; i < labels_count; i++) {
        label = malloc(sizeof(struct cmt_map_label));
        if (!label) {
            cmt_errno();
            goto error;
        }

        name = labels_val[i];
        label->name = cfl_sds_create(name);
        if (!label->name) {
            cmt_errno();
            free(label);
            goto error;
        }
        cfl_list_add(&label->_head, &metric->labels);
    }

    return metric;

 error:
    free(metric);
    return NULL;
}

void cmt_metric_destroy_map(struct cmt_metric *metric)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_sds_destroy(label->name);
        cfl_list_del(&label->_head);
        free(label);
    }

    if (metric->hist_buckets) {
        free(metric->hist_buckets);
    }
    if (metric->sum_quantiles) {
        free(metric->sum_quantiles);
    }

    cfl_list_del(&metric->_head);
    free(metric);
}

int cmt_metric_data_point_remove_label_value(struct cmt_metric *metric,
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

int cmt_metric_data_point_transform_label_value(struct cmt_metric *metric,
                                                size_t label_index,
                                                cmt_metric_transformer transformer)
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

int cmt_metric_data_point_set_label_value(struct cmt_metric *metric,
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
