# FrostyGoop Malware Deep Dive Analysis
The client/server does not work on macOS due to `github.com/rolfl/modbus`'s implementation of RTU. Eventhough we are not using the Modbus RTU implementation, the dependency runs it, so it cannot be run on macOS. I would recommend if you are a mac user to get a VM. It only runs on Windows, might applicable with another OS.

## Setting up client/server

Building the server:
```sh
go build server.go
```

Running the server:
```sh 
./server.exe
```

Building the Gooper:
```sh
go build goop.go
```

Running the Gooper with the json payload:
```sh
./goop.exe demo.json
```

## How to use go-encrypt.go
Build `go-encrypt.exe`:
```sh
go build go-encrypt.go
```

Encrypting JSON file with key file:
```sh
./go-encrypt.exe encrypt keyfile test-data.json test-data.encrypted
```

Decrypting JSON file with key file:
```sh
./go-encrypt.exe decrypt keyfile test-data.encrypted test-data-decrypted.json
```

**Key File Requirements:**
- Must contain exactly 32 bytes for AES-256 encryption
- Can be any 32-byte file (binary or text)
- Example: The included `keyfile` file contains 32 ASCII characters

**Encryption Details:**
- Uses AES-256 in Cipher Feedback Mode (CFB)
- Random IV (Initialization Vector) generated for each encryption
- Base64 encoded output for safe file storage



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