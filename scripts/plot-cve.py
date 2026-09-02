#!/usr/bin/env python3
"""Chart the CVE delta from results/cve-diff.json.

Reads the diff rather than the grype reports, so the chart cannot disagree
with the table it sits next to in docs/results.md.

usage: src/plot-cve.py [results-dir]
"""

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display on a CI runner
import matplotlib.pyplot as plt  # noqa: E402

SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible"]
COLOURS = {"source": "#4c72b0", "disk": "#c44e52"}


def main() -> int:
    results = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    diff = json.loads((results / "cve-diff.json").read_text())
    by_sev = diff["by_severity"]

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharey=False)
    width = 0.38
    x = range(len(SEVERITIES))

    panels = [
        ("All ecosystems", "a", "b",
         "includes an NVD CPE match against the kernel"),
        ("Debian packages only", "a_deb", "b_deb",
         "matched against Ubuntu's own security data"),
    ]

    for ax, (title, key_a, key_b, note) in zip(axes, panels):
        src = [by_sev[s][key_a] for s in SEVERITIES]
        dsk = [by_sev[s][key_b] for s in SEVERITIES]

        ax.bar([i - width / 2 for i in x], src, width,
               label="container", color=COLOURS["source"])
        ax.bar([i + width / 2 for i in x], dsk, width,
               label="VM disk", color=COLOURS["disk"])

        # The counts span three orders of magnitude; linear hides the small bars.
        ax.set_yscale("symlog")
        ax.set_xticks(list(x))
        ax.set_xticklabels(SEVERITIES, rotation=30, ha="right")
        ax.set_title(f"{title}\n{note}", fontsize=9)
        ax.set_ylabel("findings (log scale)")
        ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=0.3)

        for i, (s, d) in enumerate(zip(src, dsk)):
            ax.text(i - width / 2, s, str(s), ha="center", va="bottom", fontsize=7)
            ax.text(i + width / 2, d, str(d), ha="center", va="bottom", fontsize=7)

    fig.suptitle("Vulnerabilities introduced by container-to-VM conversion",
                 fontsize=11)
    fig.tight_layout()

    out = results / "cve-severity.png"
    fig.savefig(out, dpi=150)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
