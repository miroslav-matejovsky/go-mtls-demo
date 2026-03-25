package main

import (
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtls"
)

func main() {
	if err := mtls.RunDemoTLS(); err != nil {
		panic(err)
	}
}
