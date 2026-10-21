"""Tunable detection thresholds.

These trade false positives against false negatives. Document them in reports
and tune against a clean baseline before production use.
"""

SCAN_PORTS = 50  # distinct destination ports, one source -> one target
SCAN_WINDOW = 60  # seconds
BEACON_MIN_CONNS = 6
BEACON_TOLERANCE = 0.10  # gap matches if within +-10% of median
BEACON_MIN_RATIO = 0.80  # fraction of gaps that must match
DNS_LABEL_LEN = 40
DNS_ENTROPY = 3.5  # Shannon bits/char
EXFIL_BYTES = 100_000  # internal -> external bytes in one TCP stream
