package main

import (
	"log"
	"time"

	"github.com/rolfl/modbus"
)

func main() {
	// --- 1) Create a Modbus server (device identity shown to clients) ---
	serialId := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	deviceInfo := []string{
		"ACME Corporation",        // VendorName
		"Go Modbus Test Server",   // ProductCode / ProductName
		"v0.1.0",                  // MajorMinorRevision
		"https://github.com/rolfl/modbus",
	}

	srv, err := modbus.NewServer(serialId, deviceInfo)
	if err != nil {
		log.Fatalf("NewServer failed: %v", err)
	}

	// --- 2) Seed some demo values in the server’s cache (so reads have data) ---
	// Coils: 8 values    [1,1,1,1,0,0,0,0]
	// if err := srv.WriteCoilsAtomic(0, []bool{true, true, true, true, false, false, false, false}); err != nil {
	// 	log.Fatalf("seed coils failed: %v", err)
	// }
	// // Holding registers: HR[0]=1234, HR[1]=current second
	// if err := srv.WriteHoldingsAtomic(0, []int{1234, int(time.Now().Second())}); err != nil {
	// 	log.Fatalf("seed holdings failed: %v", err)
	// }

	// Optional: periodically update HR[1] with the current second
	go func() {
		for {
			_ = srv.WriteHoldingsAtomic(1, []int{int(time.Now().Second())})
			time.Sleep(1 * time.Second)
		}
	}()

	// --- 3) Allow writes from clients (FC05/06/15/16) with simple handlers ---
	// These handlers just accept whatever the client sends and store it.

	// Coils writer
	srv.RegisterCoils(0, func(_ modbus.Server, _ modbus.Atomic, address int, values []bool, current []bool) ([]bool, error) {
		// accept client-sent coil values as-is
		return values, nil
	})

	// Holdings writer
	srv.RegisterHoldings(0, func(_ modbus.Server, _ modbus.Atomic, address int, values []int, current []int) ([]int, error) {
		// accept client-sent register values as-is
		return values, nil
	})

	// --- 4) Expose the server over TCP on localhost:1502 ---
	// ServeAllUnits(srv) makes this device respond for all unit IDs (wildcard),
	// which is convenient for lab testing. You can switch to a specific map if needed.
	tcpServ, err := modbus.NewTCPServer("127.0.0.1:1502", modbus.ServeAllUnits(srv))
	if err != nil {
		log.Fatalf("NewTCPServer failed: %v", err)
	}
	log.Println("Modbus TCP server listening on 127.0.0.1:1502 (responds to any Unit ID)")

	// Block forever (or until the TCP server is closed/shutdown)
	tcpServ.WaitClosed()
}
