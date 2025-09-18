// Found this remake in the repo: http://github.com/SICRAAS/blogs
package main

import (
	"encoding/json";"fmt"
	"os"
	"sync"
	"time"

	"github.com/rolfl/modbus"
)

type Task struct {
	Code    int         `json:"Code"`
	Address int         `json:"Address"`
	Count   int         `json:"Count"`  // Used only for Read functions
	Repeat  int         `json:"Repeat"` // Optional: how many times to repeat the task
	Value   interface{} `json:"Value"`
}

type Config struct {
	Iplist []string `json:"Iplist"`
	Tasks  []Task   `json:"Tasks"`
}

func toInt(value interface{}) int {
	return int(value.(float64))
}

func toIntSlice(value interface{}) []int {
	arr := value.([]interface{})
	result := make([]int, len(arr))
	for i, v := range arr {
		result[i] = int(v.(float64))
	}
	return result
}

func toBoolSlice(value interface{}) []bool {
	arr := value.([]interface{})
	result := make([]bool, len(arr))
	for i, v := range arr {
		result[i] = int(v.(float64)) != 0
	}
	return result
}

func doTheStuff(ip string, tasks []Task, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("Connecting to Modbus server at %s...\n", ip)
	mb, err := modbus.NewTCP(ip + ":502")
	if err != nil {
		fmt.Printf("Failed to connect to %s: %v\n", ip, err)
		return
	}
	defer fmt.Printf("Disconnected from %s\n", ip)

	client := mb.GetClient(254)
	timeout := 5 * time.Second

	for _, task := range tasks {
		repeat := task.Repeat
		if repeat < 1 {
			repeat = 1
		}

		for i := 0; i < repeat; i++ {
			switch task.Code {
			case 1: // ReadCoils
				time.Sleep(1 * time.Second) // slow down output
				fmt.Printf("Task: ReadCoils, IP: %s, Address: %d, Count: %d\n", ip, task.Address, task.Count)
				data, err := client.ReadCoils(task.Address, task.Count, timeout)
				if err != nil {
					fmt.Printf("Error on ReadCoils: %v\n", err)
				} else {
					fmt.Printf("ReadCoils Result: %v\n", data)
				}
			case 3: // ReadHoldings
				time.Sleep(1 * time.Second) // slow down output
				fmt.Printf("Task: ReadHoldings, IP: %s, Address: %d, Count: %d\n", ip, task.Address, task.Count)
				data, err := client.ReadHoldings(task.Address, task.Count, timeout)
				if err != nil {
					fmt.Printf("Error on ReadHoldings: %v\n", err)
				} else {
					fmt.Printf("ReadHoldings Result: %v\n", data)
				}
			case 6: // WriteSingleHolding
				fmt.Printf("Task: WriteSingleHolding, IP: %s, Address: %d, Value: %d\n", ip, task.Address, toInt(task.Value))
				_, err := client.WriteSingleHolding(task.Address, toInt(task.Value), timeout)
				if err != nil {
					fmt.Printf("Error on WriteSingleHolding: %v\n", err)
				} else {
					fmt.Println("WriteSingleHolding completed successfully")
				}
			case 15: // WriteMultipleCoils
				switch value := task.Value.(type) {
				case []interface{}:
					bools := toBoolSlice(value)
					fmt.Printf("Task: WriteMultipleCoils, IP: %s, Address: %d, Values: %v\n", ip, task.Address, bools)
					_, err := client.WriteMultipleCoils(task.Address, bools, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleCoils: %v\n", err)
					} else {
						fmt.Println("WriteMultipleCoils completed successfully")
					}
				default:
					coil := toInt(value) != 0
					fmt.Printf("Task: WriteMultipleCoils (single), IP: %s, Address: %d, Value: %v\n", ip, task.Address, coil)
					_, err := client.WriteMultipleCoils(task.Address, []bool{coil}, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleCoils: %v\n", err)
					} else {
						fmt.Println("WriteMultipleCoils completed successfully")
					}
				}
			case 16: // WriteMultipleHoldings
				switch value := task.Value.(type) {
				case []interface{}:
					vals := toIntSlice(value)
					fmt.Printf("Task: WriteMultipleHoldings, IP: %s, Address: %d, Values: %v\n", ip, task.Address, vals)
					_, err := client.WriteMultipleHoldings(task.Address, vals, timeout)
					if err != nil {
						fmt.Printf("Error on WriteMultipleHoldings: %v\n", err)
					} else {
						fmt.Println("WriteMultipleHoldings completed successfully")
					}
				default:
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
	if len(os.Args) < 2 {
		fmt.Println("Missing config.json as program argument!")
		return
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		fmt.Printf("Failed to decode JSON: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	for _, ip := range config.Iplist {
		wg.Add(1)
		go doTheStuff(ip, config.Tasks, &wg)
	}
	wg.Wait()
	fmt.Println("All tasks completed.")
}