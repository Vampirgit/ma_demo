#!bin/bash
echo "Starting torfs..."
RUST_LOG=TRACE cargo run -- \
	--tor-data tor-data \
	--from 2025-04-25:10:00 \
	--to 2025-04-25:11:00 \
	--stream-model stream_model.json \
	--packet-model packet_model.json \
	--output-trace output/output.txt \
	--load-scale 0.0001 \
	--adv-guards-num 3000 \
	--adv-guards-bw 50000 \
	--adv-exits-num 3000 \
	--adv-exits-bw 50000
