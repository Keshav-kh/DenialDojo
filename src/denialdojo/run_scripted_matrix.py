"""Run and summarize the deterministic 32-condition harness matrix."""

import json
from collections import defaultdict

from denialdojo.experiment import scripted_sanity_matrix


def main() -> None:
    records = scripted_sanity_matrix()
    grouped: dict[tuple[str, str, int], list[bool]] = defaultdict(list)
    for record in records:
        grouped[(record.feedback_mode.value, record.defense_mode.value, record.delay)].append(
            record.leakage_success
        )
    summary = [
        {
            "feedback_mode": key[0],
            "defense_mode": key[1],
            "delay": key[2],
            "leakage_successes": sum(values),
            "runs": len(values),
        }
        for key, values in sorted(grouped.items())
    ]
    print(json.dumps({"run_count": len(records), "summary": summary}, indent=2))


if __name__ == "__main__":
    main()

