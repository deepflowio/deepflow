package zerodoc

import (
	"reflect"
	"testing"

	"gitlab.yunshan.net/yunshan/droplet-libs/app"
)

func TestMeterReverse(t *testing.T) {
	meters := []app.Meter{&FlowMeter{}, &UsageMeter{}}
	interestedFieldPairs := [][]string{
		{"PacketTx", "PacketRx"},
		{"ByteTx", "ByteRx"},
		{"L4PacketTx", "L4PacketRx"},
		{"L4ByteTx", "L4ByteRx"},
	}
	set := func(meter app.Meter, field string, value uint64) bool {
		tp := reflect.ValueOf(meter).Elem()
		if f := tp.FieldByName(field); f.CanSet() {
			f.SetUint(value)
			return true
		}
		for i := 0; i < tp.NumField(); i++ {
			if tp.Field(i).Type().Kind() != reflect.Struct {
				continue
			}
			if f := tp.Field(i).FieldByName(field); f.CanSet() {
				f.SetUint(value)
				return true
			}
		}
		return false
	}
	get := func(meter app.Meter, field string) (uint64, bool) {
		tp := reflect.ValueOf(meter).Elem()
		if f := tp.FieldByName(field); f.CanAddr() {
			return f.Uint(), true
		}
		for i := 0; i < tp.NumField(); i++ {
			if tp.Field(i).Type().Kind() != reflect.Struct {
				continue
			}
			if f := tp.Field(i).FieldByName(field); f.CanAddr() {
				return f.Uint(), true
			}
		}
		return 0, false
	}
	value0, value1 := uint64(123), uint64(456)
OUTER:
	for _, m := range meters {
		for _, pair := range interestedFieldPairs {
			if found0, found1 := set(m, pair[0], value0), set(m, pair[1], value1); found0 && found1 {
				m.Reverse()
				if value, found := get(m, pair[0]); found && value != value1 {
					t.Errorf("Reverse() of type %s is not correctly implemented", reflect.TypeOf(m).Elem().Name())
					continue OUTER
				}
				if value, found := get(m, pair[1]); found && value != value0 {
					t.Errorf("Reverse() of type %s is not correctly implemented", reflect.TypeOf(m).Elem().Name())
				}
			}
		}
	}
}
