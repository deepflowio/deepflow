all: compile

compile:
	ls *.proto | xargs protoc -o /dev/null

clean:
	rm -rf *.c *.java

.phony: all clean
