# frostygoop_analysis
FrostyGoop Malware Deep Dive Analysis

# Build Instructions
```sh
go mod init mymodbuslab
```

```sh
go get github.com/rolfl/modbus
go get golang.org/x/crypto/scrypt
```

```sh
go build server.go
```

```sh 
./server.exe
```

```sh
go build goop.go
```

```sh
./client.exe demo.json
```

## How to use go-encrypt.go
```sh
build go-encrypt.go
```

```sh
export GO_ENCRYPT_PASSPHRASE="mysupersecretpass"
```

```sh
./go-encrypt.exe encrypt test-data.json test-data.encrypted
```

```sh
./go-encrypt.exe decrypt test-data.encryped test-data.json
```



## What does task_test.json do?
1. Code 1 → Reads 8 coils from address 0 (5 times).
2. Code 3 → Reads 4 holding registers from address 0 (5 times).
3. Code 6 → Writes value 1337 to holding register at address 5 (5 times).
4. Code 15 → Writes 8 coils at address 10 with pattern [1,1,0,1,0,0,1,1] (5 times).
5. Code 16 → Writes 4 consecutive holding registers at address 20 with [10,20,30,40] (5 times).


## What is "FrostyGoop.yar"?
This is a `.yar` file with a bunch of YARA rules I found on GitHub and from reports. YARA rules are used to identify files or processes by strings, byte patterns, and conditions. In the security context, they are used to identify malware families, artifacts, and looking for suspicious activity. In `FrostyGoop.yar` I explain in depth on what each of the YARA rules are specifically detecting for.

How to run the FrostyGoop YARA rules to scan through folders and files:
```sh
yara FrostyGoop.yar /path/to/samples/
```