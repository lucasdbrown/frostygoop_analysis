// Found this remake in the repo: https://github.com/SICRAAS/blogs
package main

import (
	"encoding/json" // For parsing JSON config file
	"fmt"           // For printing output to console
	"os"            // For handling command-line arguments and file I/O
	"sync"          // For goroutines synchronization (WaitGroup)
	"time"          // For timeouts and delays

	"github.com/rolfl/modbus" // External Modbus TCP client library
)

// Task defines a single Modbus operation
type Task struct {
	Code    int         `json:"Code"`    // Modbus function code (1=ReadCoils, 3=ReadHoldings, 6=WriteSingleHolding, 15=WriteMultipleCoils, 16=WriteMultipleHoldings)
	Address int         `json:"Address"` // Starting address for the task
	Count   int         `json:"Count"`   // Number of items to read (only used for read operations)
	Repeat  int         `json:"Repeat"`  // Number of times to repeat this task
	Value   interface{} `json:"Value"`   // Value(s) to write (int or array, depending on the function)
}

// Config represents the JSON config file structure
type Config struct {
	Iplist []string `json:"Iplist"` // List of Modbus server IP addresses
	Tasks  []Task   `json:"Tasks"`  // List of tasks to perform on each IP
}

// Converts a JSON float64 into int
func toInt(value interface{}) int {
	return int(value.(float64))
}

// Converts a JSON array into a slice of ints
func toIntSlice(value interface{}) []int {
	arr := value.([]interface{})
	result := make([]int, len(arr))
	for i, v := range arr {
		result[i] = int(v.(float64))
	}
	return result
}

// Converts a JSON array into a slice of bools (nonzero = true)
func toBoolSlice(value interface{}) []bool {
	arr := value.([]interface{})
	result := make([]bool, len(arr))
	for i, v := range arr {
		result[i] = int(v.(float64)) != 0
	}
	return result
}

// taskExec executes all configured tasks for a given Modbus server IP
func taskExec(ip string, tasks []Task, wg *sync.WaitGroup) {
	defer wg.Done() // Mark goroutine as finished when function returns

	fmt.Printf("Connecting to Modbus server at %s...\n", ip)
	// Connect to Modbus TCP server (default port 502)
	mb, err := modbus.NewTCP(ip + ":502")
	if err != nil {
		fmt.Printf("Failed to connect to %s: %v\n", ip, err)
		return
	}
	defer fmt.Printf("Disconnected from %s\n", ip)

	// Create a Modbus client with unit ID 254 (broadcast or generic device ID)
	client := mb.GetClient(1)
	timeout := 5 * time.Second // Timeout for all Modbus operations

	// Loop over each configured task
	for _, task := range tasks {
		repeat := task.Repeat
		if repeat < 1 {
			repeat = 1 // Default to running once if Repeat not specified
		}

		// Execute task multiple times if needed
		for i := 0; i < repeat; i++ {
			switch task.Code {
			case 1: // ReadCoils (FC01)
				time.Sleep(1 * time.Second) // Delay to prevent spamming output
				fmt.Printf("Task: ReadCoils, IP: %s, Address: %d, Count: %d\n", ip, task.Address, task.Count)
				data, err := client.ReadCoils(task.Address, task.Count, timeout)
				if err != nil {
					fmt.Printf("Error on ReadCoils: %v\n", err)
				} else {
					fmt.Printf("ReadCoils Result: %v\n", data)
				}

			case 3: // ReadHoldings (FC03)
				time.Sleep(1 * time.Second)
				fmt.Printf("Task: ReadHoldings, IP: %s, Address: %d, Count: %d\n", ip, task.Address, task.Count)
				data, err := client.ReadHoldings(task.Address, task.Count, timeout)
				if err != nil {
					fmt.Printf("Error on ReadHoldings: %v\n", err)
				} else {
					fmt.Printf("ReadHoldings Result: %v\n", data)
				}

			case 6: // WriteSingleHolding (FC06)
				fmt.Printf("Task: WriteSingleHolding, IP: %s, Address: %d, Value: %d\n", ip, task.Address, toInt(task.Value))
				_, err := client.WriteSingleHolding(task.Address, toInt(task.Value), timeout)
				if err != nil {
					fmt.Printf("Error on WriteSingleHolding: %v\n", err)
				} else {
					fmt.Println("WriteSingleHolding completed successfully")
				}

			case 15: // WriteMultipleCoils (FC15)
				switch value := task.Value.(type) {
				case []interface{}: // If JSON array
					bools := toBoolSlice(value)
					fmt.Printf("Task: WriteMultipleCoils, IP: %s, Address: %d, Values: %v\n", ip, task.Address, bools)
					_, err := client.WriteMultipleCoils(task.Address, bools, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleCoils: %v\n", err)
					} else {
						fmt.Println("WriteMultipleCoils completed successfully")
					}
				default: // If single value
					coil := toInt(value) != 0
					fmt.Printf("Task: WriteMultipleCoils (single), IP: %s, Address: %d, Value: %v\n", ip, task.Address, coil)
					_, err := client.WriteMultipleCoils(task.Address, []bool{coil}, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleCoils: %v\n", err)
					} else {
						fmt.Println("WriteMultipleCoils completed successfully")
					}
				}

			case 16: // WriteMultipleHoldings (FC16)
				switch value := task.Value.(type) {
				case []interface{}: // If JSON array
					vals := toIntSlice(value)
					fmt.Printf("Task: WriteMultipleHoldings, IP: %s, Address: %d, Values: %v\n", ip, task.Address, vals)
					_, err := client.WriteMultipleHoldings(task.Address, vals, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleHoldings: %v\n", err)
					} else {
						fmt.Println("WriteMultipleHoldings completed successfully")
					}
				default: // If single value
					fmt.Printf("Task: WriteMultipleHoldings, IP: %s, Address: %d, Value: %d\n", ip, task.Address, toInt(value))
					_, err := client.WriteMultipleHoldings(task.Address, []int{toInt(value)}, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleHoldings: %v\n", err)
					} else {
						fmt.Println("WriteMultipleHoldings completed successfully")
					}
				}
			}
		}
	}
}

func main() {
	// Ensure config file path is passed as argument
	if len(os.Args) < 2 {
		fmt.Println("Missing config.json as program argument!")
		return
	}

	// Open the config file
	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// Parse JSON config into Config struct
	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		fmt.Printf("Failed to decode JSON: %v\n", err)
		return
	}

	// Run tasks against each IP in parallel
	var wg sync.WaitGroup
	for _, ip := range config.Iplist {
		wg.Add(1)
		go taskExec(ip, config.Tasks, &wg) // Launch goroutine per IP
	}

	// Wait for all goroutines to finish
	wg.Wait()
	fmt.Println("All tasks completed.")
}
