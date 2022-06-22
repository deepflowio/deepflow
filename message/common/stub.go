package common

//go:generate protoc --go_opt=paths=source_relative --go_out=plugins=grpc:. -I.. ../common.proto
