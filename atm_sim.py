# atm_sim.py
"""
ATM filtering simulator:
 - generates mixed legitimate and malicious ATM cells
 - processes them with ATMFilter from filtering.py
 - collects stats and plots results
"""

import random
import time
from collections import defaultdict
import matplotlib.pyplot as plt
import argparse
from filtering import ATMCell, HeaderRule, PayloadRule, ATMFilter

def generate_traffic(duration_sec=5.0, total_rate=200.0, malicious_fraction=0.1, seed=None):
    """
    Generator that yields (time_offset, ATMCell) up to duration_sec.
    total_rate = cells per second (lambda). Inter-arrival = 1/total_rate.
    We simulate deterministic spacing for reproducibility.
    """
    if seed is not None:
        random.seed(seed)
    t = 0.0
    dt = 1.0 / total_rate
    while t < duration_sec:
        # choose some VPI/VCI pairs to simulate multiple flows
        vpi = random.choice([0,1,2])
        vci = random.choice([10,20,30,40])
        is_mal = random.random() < malicious_fraction
        payload = "NORMALDATA"
        if is_mal:
            payload = "BADSIG_" + str(random.randint(0,999))
        yield t, ATMCell(vpi, vci, payload, is_mal)
        t += dt

def run_simulation(duration=5.0, rate=200.0, mal_frac=0.10, header_deny=None, signatures=None, policer_cfg=None, seed=None):
    header = HeaderRule(deny_list=header_deny)
    payload = PayloadRule(signatures=signatures)
    atm_filter = ATMFilter(header, payload, policer_cfg)

    stats = defaultdict(int)
    now_base = time.time()
    for t_offset, cell in generate_traffic(duration, rate, mal_frac, seed=seed):
        now = now_base + t_offset
        stats['total'] += 1
        if cell.is_malicious:
            stats['mal_total'] += 1
        else:
            stats['legit_total'] += 1

        action, reason = atm_filter.process(cell, now)
        if action == "drop":
            stats['dropped'] += 1
            stats[f'dropped_{reason}'] += 1
            if cell.is_malicious:
                stats['mal_dropped'] += 1
            else:
                stats['legit_dropped'] += 1
        else:
            stats['forwarded'] += 1
            if cell.is_malicious:
                stats['mal_forwarded'] += 1
            else:
                stats['legit_forwarded'] += 1
    # compute derived metrics safely
    stats['false_positive_rate'] = (stats['legit_dropped'] / stats['legit_total']) if stats.get('legit_total') else 0.0
    stats['false_negative_rate'] = (stats['mal_forwarded'] / stats['mal_total']) if stats.get('mal_total') else 0.0
    return stats

def pretty_print_stats(s, title="Simulation Results"):
    print("\n" + "="*40)
    print(title)
    print("="*40)
    for k in sorted(s.keys()):
        print(f"{k:25s} : {s[k]}")
    print("="*40 + "\n")

def plot_drops_by_reason(stats, title="Dropped cells by reason"):
    reasons = ['dropped_header','dropped_policer','dropped_payload']
    vals = [stats.get(r,0) for r in reasons]
    plt.figure(figsize=(6,4))
    bars = plt.bar(reasons, vals)
    plt.title(title)
    plt.ylabel("Number of cells")
    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, h + 1, str(int(h)), ha='center')
    plt.tight_layout()
    plt.show()

def main_cli():
    parser = argparse.ArgumentParser(description="ATM Filter Simulator")
    parser.add_argument("--duration", type=float, default=5.0, help="Duration in seconds")
    parser.add_argument("--rate", type=float, default=200.0, help="Cells per second")
    parser.add_argument("--malfrac", type=float, default=0.12, help="Malicious fraction (0..1)")
    parser.add_argument("--seed", type=int, default=1, help="Random seed")
    args = parser.parse_args()

    # Default rules for demo:
    header_deny = [(1,30)]            # block VC (1,30)
    signatures = ["BADSIG_"]          # any payload containing this is malicious
    policer_cfg = {
        (0,10): (50.0, 20.0),         # for flow (0,10): 50 cells/sec, burst 20
        (2,40): (30.0, 10.0),
    }

    stats = run_simulation(duration=args.duration, rate=args.rate, mal_frac=args.malfrac,
                           header_deny=header_deny, signatures=signatures, policer_cfg=policer_cfg, seed=args.seed)
    pretty_print_stats(stats, title=f"ATM Filter Simulator (rate={args.rate}, mal={args.malfrac})")
    plot_drops_by_reason(stats)

if __name__ == "__main__":
    main_cli()
