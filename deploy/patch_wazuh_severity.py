#!/usr/bin/env python3
"""
Patch script for connectors/wazuh/service.py
Aligns severity bands with the Wazuh dashboard:
  - Critical: Level 15+
  - High: Level 12-14
  - Medium: Level 7-11  
  - Low: Level 0-6

Run: python3 patch_wazuh_severity.py /path/to/service.py
"""
import sys

if len(sys.argv) < 2:
    print("Usage: python3 patch_wazuh_severity.py <path-to-wazuh-service.py>")
    sys.exit(1)

path = sys.argv[1]
with open(path) as f:
    content = f.read()

changes = 0

# FIX 1: severity_map in _handle_alerts_query (used for filtering)
old1 = 'severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 13}'
new1 = 'severity_map = {"low": 0, "medium": 7, "high": 12, "critical": 15}'
if old1 in content:
    content = content.replace(old1, new1)
    changes += 1
    print(f"FIX 1: severity_map for filtering: OK")
else:
    print(f"FIX 1: severity_map — NOT FOUND (may already be patched)")

# FIX 2: severity_counts in _handle_alerts_query (summary generation)
old2 = '''            if level >= 13:
                sev = "critical"
            elif level >= 10:
                sev = "high"
            elif level >= 7:
                sev = "medium"'''
new2 = '''            if level >= 15:
                sev = "critical"
            elif level >= 12:
                sev = "high"
            elif level >= 7:
                sev = "medium"'''
if old2 in content:
    content = content.replace(old2, new2)
    changes += 1
    print(f"FIX 2: severity_counts thresholds: OK")
else:
    print(f"FIX 2: severity_counts — NOT FOUND (may already be patched)")

# FIX 3: OpenSearch aggregation ranges in _handle_summary_query
old3 = '''                            {"key": "low", "from": 0, "to": 7},
                                {"key": "medium", "from": 7, "to": 10},
                                {"key": "high", "from": 10, "to": 13},
                                {"key": "critical", "from": 13},'''
new3 = '''                            {"key": "low", "from": 0, "to": 7},
                                {"key": "medium", "from": 7, "to": 12},
                                {"key": "high", "from": 12, "to": 15},
                                {"key": "critical", "from": 15},'''
if old3 in content:
    content = content.replace(old3, new3)
    changes += 1
    print(f"FIX 3: OpenSearch aggregation ranges: OK")
else:
    print(f"FIX 3: aggregation ranges — NOT FOUND (may already be patched)")

with open(path, 'w') as f:
    f.write(content)

print(f"\nApplied {changes}/3 fixes to {path}")
