"""Assembly-Assisted Malware Analysis (CSC-203) - Static PE Triage Prototype."""

from pathlib import Path
import sys

_LOCAL_SITE = Path(__file__).resolve().parent.parent / ".site-packages"
if _LOCAL_SITE.exists() and str(_LOCAL_SITE) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SITE))

__version__ = "0.5.0-rev5"
