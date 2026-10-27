"""Fut results/cu-report.md në README.md mes shënuesve CU-RESULTS."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
readme = root / "README.md"
report = (root / "results" / "cu-report.md").read_text(encoding="utf-8").strip()
start, end = "<!-- CU-RESULTS:START -->", "<!-- CU-RESULTS:END -->"

text = readme.read_text(encoding="utf-8")
if start not in text or end not in text:
    raise SystemExit("README.md nuk ka shënuesit CU-RESULTS")
before, rest = text.split(start, 1)
_, after = rest.split(end, 1)
readme.write_text(f"{before}{start}\n{report}\n{end}{after}", encoding="utf-8")
print("README.md u përditësua")
