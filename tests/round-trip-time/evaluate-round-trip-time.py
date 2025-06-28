import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

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
    
    labels = ["baseline", "halfsiphash", "siphash", "blake3", "hmac-sha1", "poly1305"]
    pretty_labels = ["SRv6", "HalfSipHash", "SipHash", "BLAKE3", "HMAC-SHA1", "Poly1305"]
    data_files = [os.path.join(script_dir + '/results', f"rtt_data_{label}.txt") for label in labels]

    plot_filename = "round-trip-time.png"
    plot_title = "Round-Trip Time Comparison For Each PoT TLV Crypto Algorithm"
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
    box = plt.boxplot(all_data, patch_artist=True, labels=valid_labels, showfliers=False)

    colors = ['#4c72b0', '#55a868', '#c44e52', '#8172b3', '#ccb974']
    for patch, color in zip(box['boxes'], colors[:len(all_data)]):
        patch.set_facecolor(color)
        patch.set_alpha(0.8)

    ax = plt.gca()
    y_min, y_max = ax.get_ylim()
    y_offset = (y_max - y_min) * 0.02

    for i, (median_line, dataset) in enumerate(zip(box['medians'], all_data), start=1):
        median_val = np.median(dataset)
        median_y = median_line.get_ydata()[0]
        ax.text(i, median_y + y_offset, f"{median_val:.2f} ms", ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.title(plot_title, fontsize=16, fontweight='bold')
    plt.ylabel(y_axis_label, fontsize=14)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    
    plt.grid(True, axis='y', linestyle='--', linewidth=0.5, alpha=0.7)
    ax = plt.gca()
    ax.yaxis.set_major_locator(ticker.MultipleLocator(0.1))
    ax.yaxis.set_minor_locator(ticker.AutoMinorLocator())
    ax.tick_params(which='minor', length=4, color='gray')
    
    plt.tight_layout()

    try:
        plot_save_path = os.path.join(script_dir, plot_filename)
        plt.savefig(plot_save_path, dpi=300)
        print(f"Box plot saved to {plot_save_path}")
    except Exception as e:
        print(f"Error saving plot: {e}", file=sys.stderr)

    print("Evaluation complete.")
