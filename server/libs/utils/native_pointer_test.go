package utils

import (
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

func TestReadNativeIntegerPointers(t *testing.T) {
	signed, unsigned := -42, ^uint(0)
	row := struct {
		Signed   *int
		Unsigned *uint
		NilInt   *int
		NilUint  *uint
	}{Signed: &signed, Unsigned: &unsigned}
	typ := reflect.TypeOf(row)
	values := reflect.ValueOf(row)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		got := GetValueByOffsetAndKind(uintptr(unsafe.Pointer(&row)), field.Offset,
			field.Type.Kind(), ToDataType(field.Type.String()))
		want := values.Field(i).Interface()
		if reflect.TypeOf(got) != field.Type || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %T %v, want %T %v", field.Name, got, got, want, want)
		}
	}
	runtime.KeepAlive(row)
}
