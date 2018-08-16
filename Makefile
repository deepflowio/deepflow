compile:
	ls *.proto | xargs protoc -o /dev/null

droplet: dfi-go zero-go

dfi-go: dfi.proto
	mkdir pbdfi
	protoc --go_out=paths=source_relative:./pbdfi $<

zero-go: zero.proto
	mkdir pbzero
	protoc --go_out=paths=source_relative:./pbzero $<

clean:
	rm -rf *.c *.go *.java
	rm -rf pbdfi pbzero

.phony: clean
