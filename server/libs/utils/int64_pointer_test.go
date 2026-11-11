package utils

import (
	"reflect"
	"runtime"
	"testing"
	"unsafe"
)

func TestInt64PointerDataType(t *testing.T) {
	value := int64(1<<40 + 123)
	row := struct{ Value *int64 }{Value: &value}
	field, _ := reflect.TypeOf(row).FieldByName("Value")
	dataType := ToDataType(field.Type.String())
	if dataType != DATATYPE_Int64Ptr {
		t.Errorf("*int64 mapped to %v, want %v", dataType, DATATYPE_Int64Ptr)
	}
	got := GetValueByOffsetAndKind(uintptr(unsafe.Pointer(&row)), field.Offset, field.Type.Kind(), dataType)
	ptr, ok := got.(*int64)
	if !ok {
		t.Fatalf("read returned %T, want *int64", got)
	}
	if ptr != &value || *ptr != value {
		t.Fatalf("read %v, want pointer to %d", ptr, value)
	}
	runtime.KeepAlive(row)
}
