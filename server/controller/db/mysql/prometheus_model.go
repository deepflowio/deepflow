/**
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mysql

import "time"

type PrometheusID struct {
	ID int `gorm:"primaryKey;column:id;type:int(10);unique;not null"`
}

type PrometheusAutoIncID struct {
	ID int `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null"`
}

type PrometheusOperatedTime struct {
	CreatedAt time.Time `gorm:"autoCreateTime;column:created_at;type:datetime" json:"CREATED_AT"`
	SyncedAt  time.Time `gorm:"autoCreateTime;column:synced_at;type:datetime" json:"SYNCED_AT"`
}

type PrometheusMetricName struct {
	PrometheusID           `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	Name                   string `gorm:"column:name;type:varchar(256);unique;not null"`
}

type PrometheusLabelName struct {
	PrometheusID           `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	Name                   string `gorm:"column:name;type:varchar(256);unique;not null"`
}

type PrometheusLabelValue struct {
	PrometheusID           `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	Value                  string `gorm:"column:value;type:text;unique;default:''"`
}

type PrometheusLabel struct {
	PrometheusAutoIncID    `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	Name                   string `gorm:"column:name;type:varchar(256);not null"`
	Value                  string `gorm:"column:value;type:text;default:''"`
}

type PrometheusMetricLabelName struct {
	PrometheusAutoIncID    `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	MetricName             string `gorm:"column:metric_name;type:varchar(256);not null"`
	LabelNameID            int    `gorm:"column:label_name_id;type:int(10);not null"`
}

type PrometheusMetricTarget struct {
	PrometheusAutoIncID    `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	MetricName             string `gorm:"column:metric_name;type:varchar(256);not null"`
	TargetID               int    `gorm:"column:target_id;type:int(10);not null"`
}

type PrometheusMetricAPPLabelLayout struct {
	PrometheusAutoIncID    `gorm:"embedded"`
	PrometheusOperatedTime `gorm:"embedded"`
	MetricName             string `gorm:"column:metric_name;type:varchar(256);not null"`
	APPLabelName           string `gorm:"column:app_label_name;type:varchar(256);not null"`
	APPLabelColumnIndex    uint8  `gorm:"column:app_label_column_index;type:tinyint(3) unsigned;not null"`
}

func (PrometheusMetricAPPLabelLayout) TableName() string {
	return "prometheus_metric_app_label_layout"
}
