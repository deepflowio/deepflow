package main

import (
	"server/controller/controller"
	"server/querier/querier"
)

func main() {
	controller.Start()
	querier.Start()
}
