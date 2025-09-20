package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rolfl/modbus"
)

func main() {
	serialId := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	deviceInfo := []string{
		"ACME Corporation",
		"Go Modbus Test Server",
		"v0.3.0",
		"https://github.com/rolfl/modbus",
	}

	srv, err := modbus.NewServer(serialId, deviceInfo)
	if err != nil {
		log.Fatalf("NewServer failed: %v", err)
	}

	coils := make([]bool, 256)
	holdings := make([]int, 256)

	// seed values
	for i := 0; i < 4; i++ {
		coils[i] = true
	}
	holdings[0] = 1234

	// Coils handler
	srv.RegisterCoils(1, func(_ modbus.Server, _ modbus.Atomic, address int, values []bool, current []bool) ([]bool, error) {
		if len(values) == 0 {
			// READ request
			end := address + len(current)
			if end > len(coils) {
				return nil, fmt.Errorf("illegal coil read range")
			}
			return coils[address:end], nil
		}
		// WRITE request
		for i, v := range values {
			if address+i < len(coils) {
				coils[address+i] = v
			}
		}
		return coils[address : address+len(values)], nil
	})

	// Holdings handler
	srv.RegisterHoldings(1, func(_ modbus.Server, _ modbus.Atomic, address int, values []int, current []int) ([]int, error) {
		if len(values) == 0 {
			// READ request
			end := address + len(current)
			if end > len(holdings) {
				return nil, fmt.Errorf("illegal holding read range")
			}
			return holdings[address:end], nil
		}
		// WRITE request
		for i, v := range values {
			if address+i < len(holdings) {
				holdings[address+i] = v
			}
		}
		return holdings[address : address+len(values)], nil
	})

	// keep HR[1] updating
	go func() {
		for {
			holdings[1] = int(time.Now().Second())
			time.Sleep(1 * time.Second)
		}
	}()

	tcpServ, err := modbus.NewTCPServer("127.0.0.1:1502", srv)
	if err != nil {
		log.Fatalf("NewTCPServer failed: %v", err)
	}
	log.Println("Modbus TCP server listening on 127.0.0.1:1502 (any Unit ID)")
	tcpServ.WaitClosed()
}
