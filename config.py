import logging
from enum import Enum
from functools import lru_cache

from pydantic import BaseSettings


class NmapPortStatus(str, Enum):
    open = 'open'
    closed = 'closed'
    filtered = 'filtered'
    unfiltered = 'unfiltered'


class ScanType(str, Enum):
    top = 'top'
    important = 'important'


class ScanerSettings(BaseSettings):
    nmap_cmd: str = 'nmap'
    top_ports: int = 15


@lru_cache()
def get_settings() -> ScanerSettings:
    """Получить синглтон конфигов."""
    return ScanerSettings()


config = get_settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('scan_factory')
