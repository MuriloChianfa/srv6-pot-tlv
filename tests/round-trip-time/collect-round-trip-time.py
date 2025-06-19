import subprocess
import re
import sys
import time
import argparse
import os

def collect_rtt(target_ip, count=100, output_filename="rtt_data.txt"):
    print(f"Pinging {target_ip} {count} times...")
    command = ["ping", "-i", "0.1", "-c", str(count), target_ip]
    rtt_values = []

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        while True:
            line = process.stdout.readline()
            if not line:
                break
            print(line.strip())
            match = re.search(r"time=([\d.]+)\s*ms", line)
            if match:
                try:
                    rtt = float(match.group(1))
                    if rtt > 6:
                        continue
                    if rtt < 2.8:
                        continue
                    rtt_values.append(rtt)
                except ValueError:
                    print(f"Warning: Could not parse RTT value from line: {line.strip()}", file=sys.stderr)

        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"Error running ping command. Return code: {process.returncode}", file=sys.stderr)
            print(f"Stderr: {stderr}", file=sys.stderr)

        if not rtt_values:
            print("No RTT values were collected.", file=sys.stderr)
            return

        output_dir = os.path.dirname(output_filename)
        if output_dir and not os.path.exists(output_dir):
             os.makedirs(output_dir)

        print(f"\nSaving {len(rtt_values)} RTT values to {output_filename}...")
        with open(output_filename, 'w') as f:
            for rtt in rtt_values:
                f.write(f"{rtt}\n")
        print("Data collection complete.")

    except FileNotFoundError:
        print(f"Error: '{command[0]}' command not found. Is ping installed and in PATH?", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    DEFAULT_TARGET_IP = "2001:db8:60:1::2"
    DEFAULT_NUM_PINGS = 300
    ALLOWED_LABELS = ["baseline", "blake3", "siphash", "halfsiphash", "poly1305"]

    parser = argparse.ArgumentParser(description="Collect ping RTT data and save to a labeled file.")
    parser.add_argument("label",
                        help="Label for the dataset.",
                        choices=ALLOWED_LABELS)
    parser.add_argument("-t", "--target",
                        default=DEFAULT_TARGET_IP,
                        help=f"Target IP address to ping (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("-c", "--count",
                        type=int,
                        default=DEFAULT_NUM_PINGS,
                        help=f"Number of pings to send (default: {DEFAULT_NUM_PINGS})")
    parser.add_argument("-o", "--output-dir",
                        default=os.path.dirname(os.path.abspath(__file__)),
                        help="Directory to save the output file (default: script's directory)")

    args = parser.parse_args()

    output_filename = f"rtt_data_{args.label}.txt"
    output_path = os.path.join(args.output_dir, output_filename)

    collect_rtt(args.target, args.count, output_path)
