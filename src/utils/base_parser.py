"""
Abstract base class for all security tool parsers.
Ensures versatility across different scanner outputs.
"""

from abc import ABC, abstractmethod

class BaseScannerParser(ABC):
    @abstractmethod
    def parse(self, raw_data):
        """
        Parse raw scanner output and return a standardized format.
        Must be implemented by all subclasses.
        """
        pass
    