"""Allow running as ``python -m converter``."""
from .cli import main
import sys

sys.exit(main())
