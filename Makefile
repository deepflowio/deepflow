all: compile

compile:
	ls *.proto | xargs protoc -I=. -I=`go env GOPATH`/src -I=`go env GOPATH`/src/github.com/gogo/protobuf/protobuf -o /dev/null

clean:
	rm -rf *.c *.java

.phony: all clean
