package main

import (
	"server/controller/controller"
	"server/querier/querier"
)

func main() {
	go func() {
		querier.Start()
	}()
	controller.Start()
}
