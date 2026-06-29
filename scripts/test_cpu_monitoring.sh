#!/bin/bash
# test_cpu_monitor.sh

# Function to spawn CPU load process
spawn_load() {
    local intensity=$1
    local name=$2
    
    python3 -c "
import time, math
end = time.time() + 300
while time.time() < end:
    start = time.time()
    while time.time() - start < 0.01 * $intensity:
        _ = math.sqrt(123456789) ** 2
    time.sleep(0.01 * (1 - $intensity))
" > /dev/null 2>&1 &    # redirect stdout and stderr
    
    local pid=$!         # save pid right away
    echo "$name: PID $pid" >&2
    echo $pid
}

echo "Spawning test processes..." >&2

# Spawn processes and capture PIDs
light_pid=$(spawn_load 0.2 "Light")
medium_pid=$(spawn_load 0.5 "Medium")
heavy_pid=$(spawn_load 0.95 "Heavy")

# Create comma-separated list to put into pid-list arg
pid_list="${light_pid},${medium_pid},${heavy_pid}"
echo -e "\nPID List: $pid_list" >&2

# Give processes time to start
sleep 0.5

# Run panhandle
echo -e "\nRunning: cargo run -- --cpu --pid-list $pid_list --poll 3" >&2
echo "==========================================================" >&2
cargo run -- --cpu --pid-list $pid_list --poll 3

# Cleanup
echo -e "\n==========================================================" >&2
echo "Cleaning up test processes..." >&2
kill $⋆⋆⋆⋆⋆_pid $medium_pid $heavy_pid 2>/dev/null
echo "Test processes terminated." >&2