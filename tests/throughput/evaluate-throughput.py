import os
import sys
import itertools
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, AutoMinorLocator
from matplotlib.lines import Line2D
import numpy as np

def load_throughput_data(filename):
    throughput_values = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                try:
                    throughput_values.append(float(line.strip()))
                except ValueError:
                    print(f"Warning: Skipping invalid line in {filename}: {line.strip()}", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: Data file not found: {filename}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An error occurred reading {filename}: {e}", file=sys.stderr)
        return None
    return throughput_values

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))

    labels = ["baseline", "halfsiphash", "siphash", "poly1305", "blake3", "hmac-sha1"]
    pretty_labels = ["SRv6", "HalfSipHash", "SipHash", "Poly1305", "BLAKE3", "HMAC-SHA1"]
    data_files = [os.path.join(script_dir + '/results', f"throughput_data_{label}.txt") for label in labels]

    all_data = []
    for fn in data_files:
        print(f"Loading data from {fn}...")
        data = load_throughput_data(fn)
        if data:
            all_data.append(data)
        else:
            print(f"Skipping {fn}", file=sys.stderr)

    if not all_data:
        sys.exit("Error: No valid throughput data loaded. Cannot generate plot.")
        sys.exit(1)
    elif len(all_data) < len(data_files):
        print(f"Warning: Plotting with {len(all_data)} datasets instead of {len(data_files)} due to loading errors.", file=sys.stderr)

    print("Generating box plot...")
    plt.style.use('classic')
    fig, ax = plt.subplots(figsize=(10, 6))

    colors = ['#6c87bb', '#79bc88', '#ce6e76', '#006faf', '#9686be', '#cdc089']
    if len(all_data) > len(colors):
        colors = list(itertools.islice(itertools.cycle(colors), len(all_data)))

    parts = ax.violinplot(all_data, vert=False, showextrema=False, widths=0.9)

    for i, body in enumerate(parts['bodies']):
        body.set_facecolor(colors[i])
        body.set_edgecolor('black')
        body.set_alpha(1.0)

    # for i, data in enumerate(all_data, start=1):
        # y = np.random.normal(i, 0.05, size=len(data))
        # ax.scatter(data, y, color='black', alpha=0.4, s=10, zorder=1)

    # for i, data in enumerate(all_data, start=1):
        # med = np.median(data)
        # mn  = np.mean(data)
        # ax.scatter(med, i, marker='o', color='black', s=35, zorder=3, label='Median' if i == 1 else "")
        # ax.scatter(mn, i, marker='D', color='red', s=40, zorder=3, label='Mean' if i==1 else "")

    for i, data in enumerate(all_data, start=1):
        mx = np.max(data)
        ax.scatter(mx, i, marker='D', color='blue', s=45, zorder=3, label='Bandwidth' if i == 1 else "")
        ax.text(mx + 35, i, f"{mx:.2f} Mbps", va='center', ha='left', fontsize=10, fontweight='bold')

    ax.xaxis.grid(True, linestyle='--', linewidth=0.7, alpha=0.7)
    ax.set_axisbelow(True)

    ax.set_yticks(range(1, len(pretty_labels) + 1))
    ax.set_yticklabels(pretty_labels, fontsize=13)
    ax.xaxis.set_major_locator(MultipleLocator(250))
    ax.set_xlabel("TCP Throughput (Mbps)", fontsize=14, labelpad=10)
    ax.set_title("Throughput Distribution For Each PoT TLV Crypto Algorithm", fontsize=16, weight='bold', pad=15)

    plt.tight_layout()
    out_path = os.path.join(script_dir, "throughput.png")
    plt.savefig(out_path, dpi=300)
    print(f"Scientific violin plot saved to {out_path}")
    print("Evaluation complete.")
