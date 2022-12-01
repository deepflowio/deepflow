package client

import (
	"github.com/deepflowys/deepflow/server/querier/common"
)

type Series struct {
	Data []interface{}
}

type SeriesSort struct {
	Series    []*Series
	SortIndex []int
	Acs       []bool
	Schemas   common.ColumnSchemas
}

func (s *SeriesSort) Len() int {
	return len(s.Series)
}

func (s *SeriesSort) Swap(i, j int) {
	s.Series[i], s.Series[j] = s.Series[j], s.Series[i]
}

func (s *SeriesSort) Less(i, j int) bool {
	for _, sortIndex := range s.SortIndex {
		switch s.Schemas[sortIndex].ValueType {
		case VALUE_TYPE_INT:
			iValue := s.Series[i].Data[sortIndex].(int)
			jValue := s.Series[j].Data[sortIndex].(int)
			return SeriesValueCompare(iValue, jValue, s.Acs[sortIndex])
		case VALUE_TYPE_STRING:
			iValue := s.Series[i].Data[sortIndex].(string)
			jValue := s.Series[j].Data[sortIndex].(string)
			return SeriesValueCompare(iValue, jValue, s.Acs[sortIndex])
		case VALUE_TYPE_FLOAT64:
			iValue := s.Series[i].Data[sortIndex].(float64)
			jValue := s.Series[j].Data[sortIndex].(float64)
			return SeriesValueCompare(iValue, jValue, s.Acs[sortIndex])
		}
	}
	return false
}

func SeriesValueCompare[T SeriersValueType](i T, j T, acs bool) bool {
	if acs {
		return i < j
	} else {
		return i > j
	}
}

type SeriersValueType interface {
	int | string | float64
}
