import matplotlib.pyplot as plt
import numpy as np
import os
import sys

def load_rtt_data(filename):
    rtt_values = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                try:
                    rtt = float(line.strip())
                    rtt_values.append(rtt)
                except ValueError:
                    print(f"Warning: Skipping invalid line in {filename}: {line.strip()}", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: Data file not found: {filename}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An error occurred reading {filename}: {e}", file=sys.stderr)
        return None
    return rtt_values

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    labels = ["baseline", "blake3", "poly1305", "siphash"]
    pretty_labels = ["SRv6", "BLAKE3", "Poly1305", "SipHash"]
    data_files = [os.path.join(script_dir, f"rtt_data_{label}.txt") for label in labels]

    plot_filename = "rtt_comparison_boxplot.png"
    plot_title = "Round-Trip Time Comparison For Each PoT TLV Crypto Algorithm Implementation"
    y_axis_label = "Round-Trip Time (ms)"

    all_data = []
    valid_labels = []

    for i, data_file in enumerate(data_files):
        print(f"Loading data from {data_file}...")
        rtt_data = load_rtt_data(data_file)
        if rtt_data:
            all_data.append(rtt_data)
            valid_labels.append(pretty_labels[i])
        else:
            print(f"Skipping {data_file} due to loading errors.")

    if len(all_data) < 1:
        print("Error: No valid data loaded. Cannot generate plot.", file=sys.stderr)
        sys.exit(1)
    elif len(all_data) < len(data_files):
         print(f"Warning: Plotting with {len(all_data)} datasets instead of {len(data_files)} due to loading errors.", file=sys.stderr)

    print("Generating box plot...")
    plt.figure(figsize=(10, 6))
    box = plt.boxplot(all_data, patch_artist=True, labels=valid_labels)

    colors = ['lightblue', 'lightgreen', 'lightcoral', 'lightsalmon']
    for patch, color in zip(box['boxes'], colors[:len(all_data)]):
        patch.set_facecolor(color)

    plt.title(plot_title)
    plt.ylabel(y_axis_label)
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)

    try:
        plot_save_path = os.path.join(script_dir, plot_filename)
        plt.savefig(plot_save_path)
        print(f"Box plot saved to {plot_save_path}")
    except Exception as e:
        print(f"Error saving plot: {e}", file=sys.stderr)

    print("Evaluation complete.")
