"""CLI entrypoint for `python -m notaffected`."""

import sys

from notaffected.cli import main

if __name__ == "__main__":
    sys.exit(main())
