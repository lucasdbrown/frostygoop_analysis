# frostygoop_analysis
FrostyGoop Malware Deep Dive Analysis



## What does task_test.json do?
1. Code 1 → Reads 8 coils from address 0 (5 times).
2. Code 3 → Reads 4 holding registers from address 0 (5 times).
3. Code 6 → Writes value 1337 to holding register at address 5 (5 times).
4. Code 15 → Writes 8 coils at address 10 with pattern [1,1,0,1,0,0,1,1] (5 times).
5. Code 16 → Writes 4 consecutive holding registers at address 20 with [10,20,30,40] (5 times).