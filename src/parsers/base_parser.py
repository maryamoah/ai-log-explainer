from abc import ABC, abstractmethod

class BaseParser(ABC):
    """
    Base class for all log parsers.
    Every parser must implement the parse() method which takes a raw log line
    and returns a normalized event dictionary or None.
    """

    @abstractmethod
    def parse(self, line: str):
        raise NotImplementedError("Subclasses must implement parse()")
