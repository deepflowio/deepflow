package common

//go:generate protoc --go_opt=paths=source_relative --gofast_out=plugins=grpc:. -I.. ../common.proto
