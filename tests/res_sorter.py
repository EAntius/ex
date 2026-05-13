import re
from collections import defaultdict

def main():
    pattern_with_size = re.compile(r"^(.*?)\s*\(size=(\d+)\):\s*([\deE\.\-]+)")
    timings = defaultdict(list)
    with open("results_to_sort.txt") as f:
        for line in f:
            line = line.strip()

            m = pattern_with_size.match(line)
            if m:
                op, size, value = m.groups()
                timings[(op, int(size))].append(float(value))
           

    # -----------------------------------------------------------------------------
    # Compute averages
    # -----------------------------------------------------------------------------
    averages = {}

    for key, values in timings.items():
        averages[key] = sum(values) / len(values)


    # -----------------------------------------------------------------------------
    # Convert to structured lists (easy to plot / export)
    # -----------------------------------------------------------------------------
    results = []

    for (op, size), avg in sorted(averages.items()):
        results.append(
            {
                "operation": op,
                "size": size,
                "average_time": avg
            }
        )


    # -----------------------------------------------------------------------------
    # Example output
    # -----------------------------------------------------------------------------
    with open("asorted_res", "a", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r['operation']} (size={r['size']}): avg={r['average_time']:.6f}s\n")
main()