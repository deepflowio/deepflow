/**
 * Copyright (c) 2023 Yunshan Networks
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

type IDField struct {
	ID int `gorm:"primaryKey;column:id;type:int(10) unsigned;unique;not null"`
}

func (i IDField) GetID() int {
	return i.ID
}

type PrometheusMetricName struct {
	IDField `gorm:"embedded"`
	Name    string `gorm:"column:name;type:varchar(256);unique;not null"`
}

func (p PrometheusMetricName) GetStr() string {
	return p.Name
}

type PrometheusLabelName struct {
	IDField `gorm:"embedded"`
	Name    string `gorm:"column:name;type:varchar(256);unique;not null"`
	// Type    uint8  `gorm:"column:type;type:tinyint(3) unsigned;not null"`
}

func (p PrometheusLabelName) GetStr() string {
	return p.Name
}

type PrometheusLabelValue struct {
	IDField `gorm:"embedded"`
	Value   string `gorm:"column:value;type:varchar(256);unique;not null"`
}

func (p PrometheusLabelValue) GetStr() string {
	return p.Value
}

type PrometheusLabel struct {
	IDField `gorm:"embedded"`
	Name    string `gorm:"column:name;type:varchar(256);not null"`
	Value   string `gorm:"column:value;type:varchar(256);not null"`
}

type PrometheusMetricTarget struct {
	IDField    `gorm:"embedded"`
	MetricName string `gorm:"column:metric_name;type:varchar(256);not null"`
	TargetID   int    `gorm:"column:target_id;type:int(10) unsigned;not null"`
}

type PrometheusMetricAPPLabelLayout struct {
	IDField             `gorm:"embedded"`
	MetricName          string `gorm:"column:metric_name;type:varchar(256);not null"`
	APPLabelName        string `gorm:"column:app_label_name;type:varchar(256);not null"`
	APPLabelColumnIndex uint8  `gorm:"column:app_label_column_index;type:tinyint(3) unsigned;not null"`
}

func (PrometheusMetricAPPLabelLayout) TableName() string {
	return "prometheus_metric_app_label_layout"
}
