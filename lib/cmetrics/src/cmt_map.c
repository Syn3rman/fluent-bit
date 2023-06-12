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
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_compat.h>

struct cmt_map *cmt_map_create(int type, struct cmt_opts *opts, int count, char **labels,
                               void *parent)
{
    int i;
    char *name;
    struct cmt_map *map;
    struct cmt_map_label *label;

    if (count < 0) {
        return NULL;
    }

    map = calloc(1, sizeof(struct cmt_map));
    if (!map) {
        cmt_errno();
        return NULL;
    }
    map->type = type;
    map->opts = opts;
    map->parent = parent;
    map->label_count = count;
    cfl_list_init(&map->label_keys);
    cfl_list_init(&map->metrics);
    cfl_list_init(&map->metric.labels);

    if (count == 0) {
        map->metric_static_set = 1;
    }

    for (i = 0; i < count; i++) {
        label = malloc(sizeof(struct cmt_map_label));
        if (!label) {
            cmt_errno();
            goto error;
        }

        name = labels[i];
        label->name = cfl_sds_create(name);
        if (!label->name) {
            cmt_errno();
            free(label);
            goto error;
        }
        cfl_list_add(&label->_head, &map->label_keys);
    }

    return map;

 error:
    cmt_map_destroy(map);
    return NULL;
}

static struct cmt_metric *metric_hash_lookup(struct cmt_map *map, uint64_t hash)
{
    struct cfl_list *head;
    struct cmt_metric *metric;

    if (hash == 0) {
        return &map->metric;
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        if (metric->hash == hash) {
            return metric;
        }
    }

    return NULL;
}

struct cmt_metric *cmt_map_metric_get(struct cmt_opts *opts, struct cmt_map *map,
                                      int labels_count, char **labels_val,
                                      int write_op)
{
    int i;
    int len;
    char *ptr;
    uint64_t hash;
    cfl_hash_state_t state;
    struct cmt_metric *metric = NULL;

    /* Enforce zero or exact labels */
    if (labels_count > 0 && labels_count != map->label_count) {
        return NULL;
    }

    /*
     * If the caller wants the no-labeled metric (metric_static_set) make sure
     * it was already pre-defined.
     */
    if (labels_count == 0) {
        /*
         * if an upcoming 'write operation' will be performed for a default
         * static metric, just initialize it and return it.
         */
        if (map->metric_static_set) {
            metric = &map->metric;
        }
        else if (write_op) {
            metric = &map->metric;
            if (!map->metric_static_set) {
                map->metric_static_set = 1;
            }
        }

        /* return the proper context or NULL */
        return metric;
    }

    /* Lookup the metric */
    cfl_hash_64bits_reset(&state);
    cfl_hash_64bits_update(&state, opts->fqname, cfl_sds_len(opts->fqname));
    for (i = 0; i < labels_count; i++) {
        ptr = labels_val[i];
        if (!ptr) {
            cfl_hash_64bits_update(&state, "_NULL_", 6);
        }
        else {
            len = strlen(ptr);
            cfl_hash_64bits_update(&state, ptr, len);
        }
    }

    hash = cfl_hash_64bits_digest(&state);
    metric = metric_hash_lookup(map, hash);

    if (metric) {
        return metric;
    }

    /*
     * If the metric was not found and the caller will not write a value, just
     * return NULL.
     */
    if (!write_op) {
        return NULL;
    }

    /* If the metric has not been found, just create it */
    metric = cmt_metric_create_map(hash, labels_count, labels_val);
    if (!metric) {
        return NULL;
    }
    cfl_list_add(&metric->_head, &map->metrics);
    return metric;
}

int cmt_map_metric_get_val(struct cmt_opts *opts, struct cmt_map *map,
                           int labels_count, char **labels_val,
                           double *out_val)
{
    double val = 0;
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(opts, map, labels_count, labels_val, CMT_FALSE);
    if (!metric) {
        return -1;
    }

    val = cmt_metric_get_value(metric);
    *out_val = val;
    return 0;
}

void cmt_map_destroy(struct cmt_map *map)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_map_label *label;
    struct cmt_metric *metric;

    cfl_list_foreach_safe(head, tmp, &map->label_keys) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_sds_destroy(label->name);
        cfl_list_del(&label->_head);
        free(label);
    }

    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        cmt_metric_destroy_map(metric);
    }

    /* histogram and quantile allocation for static metric */
    if (map->metric_static_set) {
        metric = &map->metric;

        if (map->type == CMT_HISTOGRAM) {
            if (metric->hist_buckets) {
                free(metric->hist_buckets);
            }
        }
        else if (map->type == CMT_SUMMARY) {
            if (metric->sum_quantiles) {
                free(metric->sum_quantiles);
            }
        }
    }

    free(map);
}

/* I don't know if we should leave this or promote the label type so it has its own
 * header and source files with their own constructor / destructor and an agnostic name.
 * That last bit comes from the fact that we are using the cmt_map_label type both in the
 * dimension definition list held by the map structure and the dimension value list held
 * by the metric structure.
 */

void destroy_label_list(struct cfl_list *label_list)
{
    struct cfl_list       *tmp;
    struct cfl_list       *head;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, label_list) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);

        cfl_sds_destroy(label->name);

        cfl_list_del(&label->_head);

        free(label);
    }
}

struct cmt_map_label *cmt_map_label_create(char *name)
{
    struct cmt_map_label *label;

    label = calloc(1, sizeof(struct cmt_map_label));

    if (label != NULL) {
        label->name = cfl_sds_create(name);

        if (label->name == NULL) {
            free(label);

            label = NULL;
        }

    }

    return label;
}

void cmt_map_label_destroy(struct cmt_map_label *label)
{
    if (label != NULL) {
        if (!cfl_list_entry_is_orphan(&label->_head)) {
            cfl_list_del(&label->_head);
        }

        if (label->name != NULL) {
            cfl_sds_destroy(label->name);
        }

        free(label);
    }
}

ssize_t cmt_map_get_label_index(struct cmt_map *map, char *label_name)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    ssize_t               index;

    index = 0;

    cfl_list_foreach(iterator, &map->label_keys) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (strcasecmp(label_name, label->name) == 0) {
            return index;
        }

        index++;
    }

    return -1;
}

ssize_t cmt_map_insert_label_name(struct cmt_map *map, char *label_name)
{
    struct cmt_map_label *label;
    ssize_t               index;

    label = cmt_map_label_create(label_name);

    if (label == NULL) {
        return -1;
    }

    map->label_count++;

    cfl_list_add(&label->_head, &map->label_keys);

    index = (ssize_t) cfl_list_size(&map->label_keys);
    index--;

    return index;
}

int cmt_map_contains_label(struct cmt_map *map, char *label_name)
{
    ssize_t result;

    result = cmt_map_get_label_index(map, label_name);

    if (result != -1) {
        return CMT_TRUE;
    }

    return CMT_FALSE;
}

int cmt_map_remove_label_name(struct cmt_map *map,
                              size_t label_index)
{
    struct cfl_list      *iterator;
    struct cmt_map_label *label;
    size_t                index;

    index = 0;

    cfl_list_foreach(iterator, &map->label_keys) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            cmt_map_label_destroy(label);

            return CMT_TRUE;
        }

        index++;
    }

    return CMT_FALSE;
}

int cmt_map_convert_static_metric(struct cmt_map *map,
                                  size_t label_index,
                                  char *label_value)
{
    struct cmt_metric *metric;
    int                result;
    size_t             index;
    cfl_hash_state_t   state;
    uint64_t           hash;

    cfl_hash_64bits_reset(&state);

    cfl_hash_64bits_update(&state,
                           map->opts->fqname,
                           cfl_sds_len(map->opts->fqname));

    for (index = 0 ; index < map->label_count ; index++) {
        if (index != label_index) {
            cfl_hash_64bits_update(&state,
                                   "_NULL_",
                                   6);
        }
        else {
            cfl_hash_64bits_update(&state,
                                   label_value,
                                   strlen(label_value));
        }
    }

    hash = cfl_hash_64bits_digest(&state);

    metric = cmt_metric_create_map(hash, 0, NULL);

    if (metric == NULL) {
        return CMT_FALSE;
    }

    for (index = 0 ; index < map->label_count ; index++) {
        if (index != label_index) {
            result = cmt_metric_data_point_set_label_value(metric,
                                                           index,
                                                           "",
                                                           CMT_TRUE,
                                                           CMT_TRUE);
        }
        else {
            result = cmt_metric_data_point_set_label_value(metric,
                                                           index,
                                                           label_value,
                                                           CMT_TRUE,
                                                           CMT_TRUE);
        }

        if (result != CMT_TRUE) {
            cmt_metric_destroy_map(metric);

            return CMT_FALSE;
        }
    }

    metric->val = map->metric.val;

    metric->hist_buckets = map->metric.hist_buckets;
    metric->hist_count = map->metric.hist_count;
    metric->hist_sum = map->metric.hist_sum;

    metric->sum_quantiles_set = map->metric.sum_quantiles_set;
    metric->sum_quantiles = map->metric.sum_quantiles;
    metric->sum_quantiles_count = map->metric.sum_quantiles_count;
    metric->sum_count = map->metric.sum_count;
    metric->sum_sum = map->metric.sum_sum;

    metric->timestamp = map->metric.timestamp;

    map->metric_static_set = 0;

    cfl_list_add(&metric->_head, &map->metrics);

    memset(&map->metric, 0, sizeof(struct cmt_metric));

    return CMT_TRUE;
}

int cmt_map_remove_label_value(struct cmt_map *map,
                               size_t label_index)
{
    struct cfl_list   *iterator;
    struct cmt_metric *metric;
    int                result;

    result = CMT_TRUE;

    cfl_list_foreach(iterator, &map->metrics) {
        metric = cfl_list_entry(iterator, struct cmt_metric, _head);

        result = cmt_metric_data_point_remove_label_value(metric, label_index);

        if (result == CMT_FALSE) {
            break;
        }
    }

    return result;
}

int cmt_map_set_label_value(struct cmt_map *map,
                            size_t label_index,
                            char *label_value,
                            int overwrite,
                            int insert)
{
    struct cfl_list   *iterator;
    struct cmt_metric *metric;
    int                result;

    result = CMT_TRUE;

    cfl_list_foreach(iterator, &map->metrics) {
        metric = cfl_list_entry(iterator, struct cmt_metric, _head);

        result = cmt_metric_data_point_set_label_value(metric,
                                                      label_index,
                                                      label_value,
                                                      overwrite,
                                                      insert);

        if (result == CMT_FALSE) {
            break;
        }
    }

#ifdef PROMOTE_STATIC_METRICS_ON_LABEL_INSERT
    if (map->metric_static_set == 1) {
        result = cmt_map_convert_static_metric(map,
                                               label_index,
                                               label_value);

        if(result == CMT_FALSE) {
            return CMT_FALSE;
        }
    }
#endif

    return result;
}

int cmt_map_transform_label_value(struct cmt_map *map,
                                  size_t label_index,
                                  cmt_metric_transformer transformer)
{
    struct cfl_list   *iterator;
    struct cmt_metric *metric;
    int                result;

    result = CMT_TRUE;

    cfl_list_foreach(iterator, &map->metrics) {
        metric = cfl_list_entry(iterator, struct cmt_metric, _head);

        result = cmt_metric_data_point_transform_label_value(metric,
                                                             label_index,
                                                             transformer);

        if (result == CMT_FALSE) {
            break;
        }
    }

    return result;
}

int cmt_map_update_label(struct cmt_map *map,
                         char *label_name,
                         char *label_value)
{
    ssize_t label_index;
    int     result;

    label_index = cmt_map_get_label_index(map, label_name);

    if (label_index == -1) {
        return CMT_TRUE;
    }

    result = cmt_map_set_label_value(map,
                                     label_index,
                                     label_value,
                                     CMT_TRUE,
                                     CMT_FALSE);

    if(result == CMT_FALSE) {
        return CMT_FALSE;
    }

    return CMT_TRUE;
}

int cmt_map_transform_label(struct cmt_map *map,
                            char *label_name,
                            cmt_metric_transformer transformer)
{
    ssize_t label_index;
    int     result;

    label_index = cmt_map_get_label_index(map, label_name);

    if (label_index == -1) {
        return CMT_TRUE;
    }

    result = cmt_map_transform_label_value(map,
                                           label_index,
                                           transformer);

    if(result == CMT_FALSE) {
        return CMT_FALSE;
    }

    return CMT_TRUE;
}

int cmt_map_insert_label(struct cmt_map *map,
                         char *label_name,
                         char *label_value)
{
    ssize_t label_index;
    int     label_added;
    int     result;

    label_added = CMT_FALSE;
    label_index = cmt_map_get_label_index(map, label_name);

    if (label_index == -1) {
        label_index = cmt_map_insert_label_name(map, label_name);
        label_added = CMT_TRUE;
    }

    if (label_index == -1) {
        return CMT_FALSE;
    }

    result = cmt_map_set_label_value(map,
                                     label_index,
                                     label_value,
                                     CMT_FALSE,
                                     label_added);

    if(result == CMT_FALSE) {
        return CMT_FALSE;
    }

    return CMT_TRUE;
}

int cmt_map_upsert_label(struct cmt_map *map,
                         char *label_name,
                         char *label_value)
{
    ssize_t label_index;
    int     label_added;
    int     result;

    label_added = CMT_FALSE;
    label_index = cmt_map_get_label_index(map, label_name);

    if (label_index == -1) {
        label_index = cmt_map_insert_label_name(map, label_name);
        label_added = CMT_TRUE;
    }

    if (label_index == -1) {
        return CMT_FALSE;
    }

    result = cmt_map_set_label_value(map,
                                     label_index,
                                     label_value,
                                     CMT_TRUE,
                                     label_added);

    if(result == CMT_FALSE) {
        return CMT_FALSE;
    }

    return CMT_TRUE;
}

int cmt_map_remove_label(struct cmt_map *map,
                         char *label_name)
{
    ssize_t label_index;
    int     result;

    label_index = cmt_map_get_label_index(map, label_name);

    if (label_index == -1) {
        return CMT_TRUE;
    }

    map->label_count--;

    result = cmt_map_remove_label_name(map, label_index);

    if(result == CMT_TRUE) {
        result = cmt_map_remove_label_value(map, label_index);
    }

    return result;
}
