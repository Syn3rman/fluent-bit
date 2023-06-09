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

#ifndef CMT_LABEL_H
#define CMT_LABEL_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>

typedef int (*label_transformer)(struct cmt_metric *, cfl_sds_t *value);

struct cmt_label {
    cfl_sds_t key;             /* Label key */
    cfl_sds_t val;             /* Label value */
    struct cfl_list _head;      /* Link to list cmt_labels->list */
};

struct cmt_labels {
    struct cfl_list list;
};

struct cmt_labels *cmt_labels_create();
void cmt_labels_destroy(struct cmt_labels *labels);
int cmt_labels_add_kv(struct cmt_labels *labels, char *key, char *val);
int cmt_labels_count(struct cmt_labels *labels);

int cmt_contains_static_label(struct cmt *metrics_context,
                              char *label_name);
int cmt_update_static_label(struct cmt *metrics_context,
                            char *label_name,
                            char *label_value);
int cmt_remove_static_label(struct cmt *metrics_context,
                            char *label_name);
int cmt_transform_static_label(struct cmt *metrics_context,
                               char *label_name,
                               label_transformer transformer);

int cmt_contains_dynamic_label(struct cmt *metrics_context,
                               char *label_name);
int cmt_insert_dynamic_label(struct cmt *metrics_context,
                             char *label_name,
                             char *label_value);
int cmt_update_dynamic_label(struct cmt *metrics_context,
                             char *label_name,
                             char *label_value);
int cmt_transform_dynamic_label(struct cmt *metrics_context,
                                char *label_name,
                                label_transformer transformer);
int cmt_upsert_dynamic_label(struct cmt *metrics_context,
                             char *label_name,
                             char *label_value);
int cmt_remove_dynamic_label(struct cmt *metrics_context,
                             char *label_name);

void cmt_label_destroy(struct cmt_label *label);

int cmt_data_point_remove_label_value(struct cmt_metric *metric,
                                      size_t label_index);
int cmt_data_point_transform_label_value(struct cmt_metric *metric,
                                         size_t label_index,
                                         label_transformer transformer);
int cmt_data_point_set_label_value(struct cmt_metric *metric,
                                   size_t label_index,
                                   char *label_value,
                                   int overwrite,
                                   int insert);

#endif
