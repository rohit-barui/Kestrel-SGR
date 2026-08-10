#!/usr/bin/env python3
"""
Enforce strict coverage thresholds:

* Overall line coverage ≥ 95 %
* Every source file (core/*.py, skills/*.py) must have ≥ 99 % line coverage
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Make emoji output safe on Windows consoles (cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

COVERAGE_XML = Path('coverage.xml')
FAIL = False

if not COVERAGE_XML.is_file():
    sys.stderr.write('❌ coverage.xml not found – did you run pytest --cov?\n')
    sys.exit(1)

tree = ET.parse(COVERAGE_XML)
root = tree.getroot()

# Overall coverage
overall_percent = float(root.attrib.get('line-rate', '0')) * 100
if overall_percent < 95.0:
    sys.stderr.write(f'❌ Overall coverage {overall_percent:.2f}% < 95%\n')
    FAIL = True
else:
    print(f'✅ Overall coverage {overall_percent:.2f}%')

# Per‑file check
for cls in root.iter('class'):
    filename = cls.attrib.get('filename', '')
    if not (filename.startswith('core/') or filename.startswith('skills/')):
        continue
    file_cov = float(cls.attrib.get('line-rate', '0')) * 100
    if file_cov < 99.0:
        sys.stderr.write(f'❌ {filename} coverage {file_cov:.2f}% < 99%\n')
        FAIL = True

if FAIL:
    sys.exit(1)
else:
    print('✅ All source files meet ≥ 99 % line coverage')
