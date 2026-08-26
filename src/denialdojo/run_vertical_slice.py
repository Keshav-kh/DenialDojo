"""CLI for the first reproducible DenialDojo experiment."""

import json

from denialdojo.experiment import paired_vertical_slice


def main() -> None:
    records = paired_vertical_slice(delay=2)
    print(json.dumps([record.model_dump(mode="json") for record in records], indent=2))


if __name__ == "__main__":
    main()

