package clickhouse

import (
	"metaflow/querier/engine/clickhouse/view"
	"strconv"
)

type Callback struct {
	Args     []interface{}
	Function func([]interface{}) func(columns []interface{}, values []interface{}) []interface{}
}

func (c *Callback) Format(m *view.Model) {
	m.AddCallback(c.Function(c.Args))
}

func TimeFill(args []interface{}) func(columns []interface{}, values []interface{}) (newValues []interface{}) {
	// group by time时的补点
	return func(columns []interface{}, values []interface{}) (newValues []interface{}) {
		m := args[0].(*view.Model)
		var timeFieldIndex int
		// 取出time字段对应的下标
		for i, column := range columns {
			if column.(string) == m.Time.Alias {
				timeFieldIndex = i
				break
			}
		}
		// start和end取整
		start := (int(m.Time.TimeStart)+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8
		end := (int(m.Time.TimeEnd)+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8
		// 获取排序
		orderby := "asc"
		for _, node := range m.Orders.Orders {
			order := node.(*view.Order)
			if order.SortBy == m.Time.Alias {
				orderby = order.OrderBy
				break
			}
		}
		// 补点后切片长度
		intervalLength := (end-start)/m.Time.Interval + 1
		newValues = make([]interface{}, intervalLength)
		// 将查询数据结果写入newValues切片
		for _, value := range values {
			record := value.([]interface{})
			// 获取record在补点切片中的位置
			timeIndex := (record[timeFieldIndex].(int) - start) / m.Time.Interval
			newValues[timeIndex] = value
		}
		var timestamp int
		// 针对newValues中缺少的时间点进行补点
		for i, value := range newValues {
			if value == nil {
				newValue := make([]interface{}, len(columns))
				if m.Time.Fill != "null" {
					for i := range newValue {
						if intField, err := strconv.Atoi(m.Time.Fill); err == nil {
							newValue[i] = int(intField)
						} else {
							newValue[i] = m.Time.Fill
						}
					}
				}
				if orderby == "asc" {
					timestamp = start + i*m.Time.Interval
				} else {
					timestamp = end - i*m.Time.Interval
				}
				newValue[timeFieldIndex] = timestamp
				newValues[i] = newValue
			}
		}
		return newValues
	}
}
