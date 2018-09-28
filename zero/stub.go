package zero

//go:generate protoc -I=.. -I=`go env GOPATH`/src -I=`go env GOPATH`/src/github.com/gogo/protobuf/protobuf --gogo_out=plugins=grpc:. zero.proto
