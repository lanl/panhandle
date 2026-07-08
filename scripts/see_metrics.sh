#!/bin/bash
# script to simply print the output of each panhandle metric option once

touch tmp_metrics.txt

cargo run -- --cpu --gpu --memory --memory-faults 0 --socket --io --poll 3 > tmp_metrics.txt &

# wait for panhandle to start writing
while [ ! -s tmp_metrics.txt ]; do
    sleep 1
done

PANHANDLE_PID=$(pgrep -f "panhandle")

# wait until all metrics collected (I/O is last)
while ! grep -q "Read_Count" tmp_metrics.txt; do
    sleep 1
done

# stop panhandle before reading results
sudo kill -INT $PANHANDLE_PID
wait $PANHANDLE_PID 2>/dev/null

# now display results
echo "CPU Message:"
grep -m1 "CPU%" tmp_metrics.txt
echo ""

echo "GPU Message:"
grep -m1 "VRAM%" tmp_metrics.txt
echo ""

echo "Memory Message:"
grep -m1 "RSS" tmp_metrics.txt
echo ""

echo "Memory Fault Message:"
grep -m1 "Major Faults" tmp_metrics.txt
echo ""

echo "Socket Message:"
grep -m1 "ESTAB" tmp_metrics.txt
echo ""

echo "I/O Message:"
grep -m1 "Read_Count" tmp_metrics.txt
echo ""

rm tmp_metrics.txt