import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "workload"), str(ROOT / "cli"), str(ROOT / "control-plane" / "launcher")]
