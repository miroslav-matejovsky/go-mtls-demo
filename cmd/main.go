package main

import (
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tls"
)

func main() {
	if err := tls.RunDemoTLS(); err != nil {
		panic(err)
	}
}
