"""pcaplens — offline PCAP triage for SOC / DFIR analysts."""

__version__ = "0.1.0"
__author__ = "Benjamin Christy"

from pcaplens.analyze import AnalysisResult, analyze_pcap

__all__ = ["AnalysisResult", "analyze_pcap", "__version__"]
