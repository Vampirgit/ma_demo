#!bin/bash

# Create output directory if it doesn't exist
mkdir -p output

# Generate timestamp for the output file
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE="output/trace_${TIMESTAMP}.txt"
SUMMARY_FILE="output/summary_${TIMESTAMP}.txt"

echo "Starting torfs with output to ${OUTPUT_FILE}..."

# Run the command and pipe stdout to the output file
RUST_LOG=INFO cargo run -- \
    --tor-data tor-data \
    --from 2025-01-25:10:00 \
    --to 2025-01-25:16:00 \
    --stream-model stream_model.json \
    --packet-model packet_model.json \
    --output-trace output/output.txt \
    --load-scale 1 \
    --adv-guards-num 100 \
    --adv-guards-bw 40000 \
    --adv-exits-num 100 \
    --adv-exits-bw 40000 > "$OUTPUT_FILE" 2>&1

echo "Execution complete. Output saved to ${OUTPUT_FILE}"
echo "Generating summary statistics..."

# Call the Python analysis script
python3 create_statistics.py "$OUTPUT_FILE" "$SUMMARY_FILE"

echo "Summary statistics saved to ${SUMMARY_FILE}"
