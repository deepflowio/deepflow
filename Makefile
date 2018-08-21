all: compile droplet

compile:
	ls *.proto | xargs protoc -o /dev/null

droplet: dfi-go zero-go

dfi-go: dfi.proto
	protoc --go_out=paths=source_relative:./pbdfi $<

zero-go: zero.proto
	protoc --go_out=paths=source_relative:./pbzero $<

clean:
	rm -rf *.c *.java

.phony: all clean
