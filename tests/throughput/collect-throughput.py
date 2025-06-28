import subprocess
import json
import sys
import time
import argparse
import os

def collect_throughput(target_ip, duration=10, num_tests=5, size=1306, output_filename="throughput_data.txt"):
    throughput_values = []
    base_command = ["iperf3", "-c", target_ip, "-t", str(duration), "-b", "10G", "--json", "-M", str(size), "-i", "0.1"]

    for i in range(num_tests):
        print(f"Test {i+1}/{num_tests}: Running iperf3 measurement on {target_ip}...")
        print(' '.join(base_command))
        try:
            result = subprocess.run(base_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as json_err:
                print(f"Test {i+1}: Failed parsing JSON output: {json_err}", file=sys.stderr)
                print(f"Stderr: {result.stderr}", file=sys.stderr)
                continue

            if "error" in data:
                print(f"Test {i+1}: iperf3 error: {data['error']}", file=sys.stderr)
                continue

            intervals = data.get("intervals", [])
            if intervals:
                for idx, interval in enumerate(intervals):
                    bps = None
                    if "sum" in interval and "bits_per_second" in interval["sum"]:
                        bps = interval["sum"]["bits_per_second"]
                    elif "streams" in interval and interval["streams"]:
                        bps = interval["streams"][0].get("bits_per_second")
                    if bps is not None:
                        mbps = bps / 1e6
                        throughput_values.append(mbps)
                        print(f"Test {i+1} Interval {idx+1}: {mbps:.2f} Mb/s")
                    else:
                        print(f"Test {i+1} Interval {idx+1}: bits_per_second missing.", file=sys.stderr)
            else:
                print(f"Test {i+1}: No intervals found in iperf3 JSON output.", file=sys.stderr)
        except Exception as e:
            print(f"Test {i+1}: Exception occurred: {e}", file=sys.stderr)
        time.sleep(1)
    
    if not throughput_values:
        print("No throughput values collected.", file=sys.stderr)
        return

    output_dir = os.path.dirname(output_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"\nSaving {len(throughput_values)} throughput values to {output_filename}...")
    try:
        with open(output_filename, 'w') as f:
            for val in throughput_values:
                f.write(f"{val}\n")
        print("Throughput data collection complete.")
    except Exception as e:
        print(f"Error writing to file: {e}", file=sys.stderr)

if __name__ == "__main__":
    DEFAULT_TARGET_IP = "2001:db8:60:1::2"
    DEFAULT_DURATION = 10
    DEFAULT_NUM_TESTS = 5
    ALLOWED_LABELS = ["baseline", "blake3", "siphash", "halfsiphash", "poly1305", "hmac-sha1"]
    SIZES = {
        "baseline": 1308, # mss 1356
        "blake3": 1228, # mss 1276
        "hmac-sha1": 1252, # mss 1300
        "siphash": 1276, # mss 1324
        "halfsiphash": 1316, # mss 1332
        "poly1305": 1260, # mss 1308
    }

    parser = argparse.ArgumentParser(description="Collect iperf3 throughput data and save to a labeled file.")
    parser.add_argument("label",
                        help="Label for the dataset.",
                        choices=ALLOWED_LABELS)
    parser.add_argument("-t", "--target",
                        default=DEFAULT_TARGET_IP,
                        help=f"Target IP address to connect (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("-d", "--duration",
                        type=int,
                        default=DEFAULT_DURATION,
                        help=f"Duration of each iperf3 test in seconds (default: {DEFAULT_DURATION})")
    parser.add_argument("-n", "--num-tests",
                        type=int,
                        default=DEFAULT_NUM_TESTS,
                        help=f"Number of tests to run (default: {DEFAULT_NUM_TESTS})")
    parser.add_argument("-o", "--output-dir",
                        default=os.path.dirname(os.path.abspath(__file__)),
                        help="Directory to save the output file (default: script's directory)")

    args = parser.parse_args()

    output_filename = f"throughput_data_{args.label}.txt"
    output_path = os.path.join(args.output_dir, output_filename)

    collect_throughput(args.target, args.duration, args.num_tests, SIZES[args.label], output_path)
