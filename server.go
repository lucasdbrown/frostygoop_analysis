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

	// Register handlers for multiple Unit IDs to ensure compatibility
	coilHandler := func(_ modbus.Server, _ modbus.Atomic, address int, values []bool, current []bool) ([]bool, error) {
		log.Printf("Coils request: address=%d, values=%v, current=%v", address, values, current)
		if len(values) == 0 {
			// READ request
			end := address + len(current)
			if end > len(coils) {
				return nil, fmt.Errorf("illegal coil read range")
			}
			result := coils[address:end]
			log.Printf("Coils read result: %v", result)
			return result, nil
		}
		// WRITE request
		for i, v := range values {
			if address+i < len(coils) {
				coils[address+i] = v
			}
		}
		result := coils[address : address+len(values)]
		log.Printf("Coils write result: %v", result)
		return result, nil
	}

	holdingHandler := func(_ modbus.Server, _ modbus.Atomic, address int, values []int, current []int) ([]int, error) {
		log.Printf("Holdings request: address=%d, values=%v, current=%v", address, values, current)
		if len(values) == 0 {
			// READ request
			end := address + len(current)
			if end > len(holdings) {
				return nil, fmt.Errorf("illegal holding read range")
			}
			result := holdings[address:end]
			log.Printf("Holdings read result: %v", result)
			return result, nil
		}
		// WRITE request
		for i, v := range values {
			if address+i < len(holdings) {
				holdings[address+i] = v
			}
		}
		result := holdings[address : address+len(values)]
		log.Printf("Holdings write result: %v", result)
		return result, nil
	}

	// Register handlers for Unit IDs 0, 1, and 254 (common defaults)
	srv.RegisterCoils(0, coilHandler)
	srv.RegisterCoils(1, coilHandler)
	srv.RegisterCoils(254, coilHandler)
	
	srv.RegisterHoldings(0, holdingHandler)
	srv.RegisterHoldings(1, holdingHandler)
	srv.RegisterHoldings(254, holdingHandler)

	// keep HR[1] updating
	go func() {
		for {
			holdings[1] = int(time.Now().Second())
			time.Sleep(1 * time.Second)
		}
	}()

	tcpServ, err := modbus.NewTCPServer("127.0.0.1:1502", modbus.ServeAllUnits(srv))
	if err != nil {
		log.Fatalf("NewTCPServer failed: %v", err)
	}
	log.Println("Modbus TCP server listening on 127.0.0.1:1502 (any Unit ID)")
	tcpServ.WaitClosed()
}
