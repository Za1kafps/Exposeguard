package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("exposeguard: missing command")
		fmt.Println("usage: exposeguard scan")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		fmt.Println("exposeguard: scan started")
		fmt.Println("exposeguard: no checks implemented yet")
	default:
		fmt.Printf("exposeguard: unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}
