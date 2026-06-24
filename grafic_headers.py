import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

BLUE  = "#3A7EBF" 
RED   = "#C0392B"
GRAY  = "#AAAAAA"

plt.rcParams.update({
    "font.family":     "serif",
    "font.size":       11,
    "axes.titlesize":  13,
    "axes.titleweight":"bold",
    "axes.spines.top":    False,
    "axes.spines.right":  False,
})


def add_value_labels(ax, bars, fontsize=10):
    for bar in bars:
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + 1.2,
            f"{h:.1f}%",
            ha="center", va="bottom",
            fontsize=fontsize, fontweight="bold",
            color="#333333"
        )


yahoo_headers = [
    "Reply-To\n(cu adresă reală)",
    "DKIM-\nSignature",
    "Received-SPF",
    "Authentication-\nResults",
]

yahoo_legit = [88.7, 91.6, 100.0, 100.0]
yahoo_scam  = [ 7.5, 93.2, 100.0, 100.0]


tuiasi_headers = [
    "Reply-To\n(cu adresă reală)",
    "DKIM-\nSignature",
    "Received-SPF",
    "Authentication-\nResults",
    "X-MailScanner\nSpamCheck"
]

tuiasi_legit = [51.8, 75.4, 0.6, 5.4, 82.1]
tuiasi_scam  = [26.8, 35.7, 5.4, 1.0,  64.3]

hotmail_headers = [
    "Reply-To\n(cu adresă reală)",
    "DKIM-\nSignature",
    "Received-SPF",
    "Authentication-\nResults",
]

hotmail_legit = [67.4, 99.9, 100.0, 100.0]
hotmail_scam  = [ 8.3, 16.7, 100.0, 100.0]


def plot_coverage(headers, legit_vals, scam_vals, title, filename, note=None):

    n = len(headers)
    x = np.arange(n)
    width = 0.35

    fig, ax = plt.subplots(figsize=(max(7, n * 2.0), 6))

    bars_l = ax.bar(x - width / 2, legit_vals, width,
                    label="Legitime", color=BLUE, alpha=0.88,
                    edgecolor="white", linewidth=0.8)
    bars_s = ax.bar(x + width / 2, scam_vals,  width,
                    label="Scam",     color=RED,  alpha=0.88,
                    edgecolor="white", linewidth=0.8)

    add_value_labels(ax, bars_l)
    add_value_labels(ax, bars_s)

    ax.set_xticks(x)
    ax.set_xticklabels(headers, fontsize=10.5)
    ax.set_ylabel("Procent e-mailuri (%)", fontsize=11)
    ax.set_ylim(0, 115)
    ax.set_title(title, pad=14)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.grid(axis="y", linestyle="--", alpha=0.35, color=GRAY)
    ax.set_axisbelow(True)

    legend_patches = [
        mpatches.Patch(color=BLUE, alpha=0.88, label="Legitime"),
        mpatches.Patch(color=RED,  alpha=0.88, label="Scam"),
    ]
    ax.legend(handles=legend_patches, loc="upper right",
            bbox_to_anchor=(1, 1.15),
            framealpha=0.85, fontsize=10.5)

    if note:
        fig.text(0.5, -0.02, note, ha="center", fontsize=9,
                 color="#555555", style="italic",
                 wrap=True)

    plt.tight_layout()
    plt.savefig(filename, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"Salvat: {filename}")


plot_coverage(
    headers    = yahoo_headers,
    legit_vals = yahoo_legit,
    scam_vals  = yahoo_scam,
    title      = "",
    filename   = "D:/An 4/Licenta/final_cod/eda/grafic_yahoo.png",
    note       = (
        "* Reply-To (cu adresă reală): headerul este prezent în 100% din e-mailuri în ambele clase, "
        "însă valoarea este goală în 11.3% din legitime și 92.5% din scam. "
        "Graficul raportează procentul e-mailurilor cu adresă Reply-To efectivă."
    ),
)

plot_coverage(
    headers    = tuiasi_headers,
    legit_vals = tuiasi_legit,
    scam_vals  = tuiasi_scam,
    title      = "",
    filename   = "D:/An 4/Licenta/final_cod/eda/grafic_tuiasi.png",
    note       = (
        "* Reply-To (cu adresă reală): headerul este prezent în 100% din e-mailuri în ambele clase, "
        "însă valoarea este goală în 48.2% din legitime și 73.2% din scam. "
        "Graficul raportează procentul e-mailurilor cu adresă Reply-To efectivă."
    ),
)

plot_coverage(
    headers    = hotmail_headers,
    legit_vals = hotmail_legit,
    scam_vals  = hotmail_scam,
    title      = "",
    filename   = "D:/An 4/Licenta/final_cod/eda/grafic_hotmail.png",
    note       = (
        "* Reply-To (cu adresă reală): headerul este prezent în 100% din e-mailuri în ambele clase, "
        "însă valoarea este goală în 32.6% din legitime și 91.7% din scam. "
        "Graficul raportează procentul e-mailurilor cu adresă Reply-To efectivă."
    ),
)