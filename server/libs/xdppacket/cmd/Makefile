MESSAGE = github.com/deepflowio/deepflow/message

afpacket-debug:
	go build -gcflags 'all=-N -l' -o benchTest_afpacket ./afpacket/main.go

afpacket:
	go build -o benchTest_afpacket ./afpacket/main.go

xdp-debug: 
	go build -gcflags 'all=-N -l' -tags="xdp" -o benchTest ./xdp/main.go

xdp: 
	go build -tags="xdp" -o benchTest ./xdp/main.go

clean:
	rm -f benchTest* 

.DEFAULT_GOAL := xdp

.PHONY: xdp afpacket xdp-debug afpacket-debug clean
