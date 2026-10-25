"""pcaplens — offline PCAP triage for SOC / DFIR analysts."""

__version__ = "0.1.0"
__author__ = "Benjamin Christy"

from pcaplens.analyze import AnalysisResult, analyze_pcap
from pcaplens.parse import ParseLimits, PcapParseError
from pcaplens.thresholds import ProfileError, Thresholds, load_profile

__all__ = [
    "AnalysisResult",
    "PcapParseError",
    "ParseLimits",
    "ProfileError",
    "Thresholds",
    "analyze_pcap",
    "load_profile",
    "__version__",
]
