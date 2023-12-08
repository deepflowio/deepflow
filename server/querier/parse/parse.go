/*
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

package parse

import (
	"github.com/xwb1989/sqlparser"

	"github.com/deepflowio/deepflow/server/querier/engine"
)

type Parser struct {
	Engine engine.Engine
}

func NewParser() *Parser {
	return &Parser{}
}

// 解析入口，解析结果写入Model
func (p *Parser) ParseSQL(sql string) error {
	// sql解析
	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		return err
	}

	pStmt := stmt.(*sqlparser.Select)
	// From解析
	if pStmt.From != nil {
		fromErr := p.Engine.TransFrom(pStmt.From)
		if fromErr != nil {
			return fromErr
		}
	}

	// DerivativeGroupBy解析
	if pStmt.GroupBy != nil {
		groupErr := p.Engine.TransDerivativeGroupBy(pStmt.GroupBy)
		if groupErr != nil {
			return groupErr
		}
	}

	// Select解析
	var selectErr error
	if pStmt.SelectExprs != nil {
		selectErr = p.Engine.TransSelect(pStmt.SelectExprs)
		if selectErr != nil {
			return selectErr
		}
	}

	// Where 解析
	if pStmt.Where != nil {
		whereErr := p.Engine.TransWhere(pStmt.Where)
		if whereErr != nil {
			return whereErr
		}
	}

	// GroupBy解析
	if pStmt.GroupBy != nil {
		groupErr := p.Engine.TransGroupBy(pStmt.GroupBy)
		if groupErr != nil {
			return groupErr
		}
	}

	if pStmt.Having != nil {
		havingErr := p.Engine.TransHaving(pStmt.Having)
		if havingErr != nil {
			return havingErr
		}
	}

	// OrderBy解析
	if pStmt.OrderBy != nil {
		orderErr := p.Engine.TransOrderBy(pStmt.OrderBy)
		if orderErr != nil {
			return orderErr
		}
	}

	// Limit解析
	if pStmt.Limit != nil {
		limitErr := p.Engine.TransLimit(pStmt.Limit)
		if limitErr != nil {
			return limitErr
		}
	}
	return nil
}
