package portscan_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/DaniilGrigoritsa/portscan"
)

func Example() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	results, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, portscan.List(port))
	if err != nil {
		log.Fatal(err)
	}
	for r := range results {
		fmt.Println(r.Host, r.State)
	}
}

func ExampleMerge() {
	ports := portscan.Merge(
		portscan.Range(1, 1024),
		portscan.List(8080, 8443, 80),
		portscan.Range(8000, 8100),
	)
	fmt.Println(ports, ports.Len())
}

func ExampleRange_invalid() {
	fmt.Println(portscan.Range(1000, 1).Err())
	fmt.Println(portscan.List(0).Err())
}
