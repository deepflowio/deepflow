package genesis

//go:generate protoc --go_opt=paths=source_relative --go_out=plugins=grpc:. -I.. ../genesis.proto
