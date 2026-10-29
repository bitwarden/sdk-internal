# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "numpy"]
# ///
"""Plot false positive rate per query vs bytes stored per hash.

Usage: uv run plot_fp_rate.py
"""

import matplotlib.pyplot as plt
import numpy as np

# Dataset: ~1971 rows per 5-nibble range (hibp-ranges/) × 16^5 ranges
ROWS_PER_RANGE = 1971
PREFIX_SPACE = 16**5
TOTAL_HASHES = ROWS_PER_RANGE * PREFIX_SPACE
BITS_PER_BYTE = 8
GB = 1e9

# 1e9 queries / year → one false positive per year at this rate
QUERIES_PER_YEAR = 1e9

BYTES = np.arange(4, 17)
OUTPUT_FILE = "fp_rate.png"

# Reference palette (dataviz skill), light mode
SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"
SERIES_FLAT = "#2a78d6"
SERIES_BUCKETED = "#eb6834"


def fp_rate(bytes_stored: np.ndarray, candidates: float) -> np.ndarray:
    """P(random non-member matches any of `candidates` truncated hashes)."""
    space = 2.0 ** (bytes_stored * BITS_PER_BYTE)
    return -np.expm1(-candidates / space)


def main() -> None:
    flat = fp_rate(BYTES, TOTAL_HASHES)
    bucketed = fp_rate(BYTES, ROWS_PER_RANGE)

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    ax.plot(BYTES, flat, color=SERIES_FLAT, linewidth=2, marker="o", markersize=6, label="Whole set")
    ax.plot(BYTES, bucketed, color=SERIES_BUCKETED, linewidth=2, marker="o", markersize=6, label="Within 5-nibble bucket")
    ax.set_yscale("log")

    # Threshold: rate giving one false positive per year across all users
    threshold = 1 / QUERIES_PER_YEAR
    ax.axhline(threshold, color=TEXT_SECONDARY, linestyle="--", linewidth=1)
    ax.text(BYTES[-1], threshold * 2, "1 false positive / year at 10⁹ queries", color=TEXT_SECONDARY, ha="right", fontsize=9)

    # Direct labels at the right end of each series
    ax.text(BYTES[-1] + 0.2, flat[-1], "Whole set", color=TEXT_PRIMARY, va="center", fontsize=9)
    ax.text(BYTES[-1] + 0.2, bucketed[-1], "Bucketed", color=TEXT_PRIMARY, va="center", fontsize=9)

    # X ticks show bytes and total memory, e.g. "8 B\n16.6 GB"
    ax.set_xticks(BYTES)
    ax.set_xticklabels([f"{b} B\n{b * TOTAL_HASHES / GB:.1f} GB" for b in BYTES], fontsize=8, color=TEXT_SECONDARY)
    ax.tick_params(axis="y", colors=TEXT_SECONDARY)
    ax.set_xlim(BYTES[0] - 0.3, BYTES[-1] + 1.3)

    ax.set_xlabel("Bytes stored per hash (total for 2.07 B hashes, no count)", color=TEXT_PRIMARY)
    ax.set_ylabel("False positive rate per query", color=TEXT_PRIMARY)
    ax.set_title("Truncated hash size vs false positive rate", color=TEXT_PRIMARY, loc="left")

    ax.grid(True, which="major", color=GRID, linewidth=0.8)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.legend(frameon=False, labelcolor=TEXT_PRIMARY, loc="lower left")

    fig.tight_layout()
    fig.savefig(OUTPUT_FILE, dpi=150, facecolor=SURFACE)
    print(f"Saved {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
