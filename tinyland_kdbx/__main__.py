"""Allow running as python -m tinyland_kdbx."""
import sys

from tinyland_kdbx.cli import main

if __name__ == "__main__":
    sys.exit(main())
