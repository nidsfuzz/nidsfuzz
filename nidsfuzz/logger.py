import datetime
import os
import sys

from loguru import logger as log
from pathlib import Path

log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

# Remove the default stdout handler
log.remove()

# Add a console logger
log.add(
    sys.stdout,
    format=log_format,
    level="DEBUG",
    filter=lambda record: True  # Display all log messages
)

class LoggerManager:

    def __init__(self,
                 anchor: str = None):
        if anchor is None:
            # Generate a unique identifier for the log directory
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
            self.anchor = Path(__file__).parent.parent / 'logs' / timestamp
        else:
            self.anchor = Path(anchor)

    def setup_logger(self, module_name: str, level: str = "INFO"):
        log_file = self.anchor / f'{module_name}.log'
        log.add(
            sink=f'{log_file}',
            format=log_format,
            level=level,  # DEBUG or INFO
            rotation="100 MB",
            encoding="utf-8",
            filter=lambda  record: record["extra"].get("module") == module_name
        )
        return self.get_logger(module_name)

    def get_logger(self, module_name: str):
        return log.bind(module=module_name)


# Check the environment variable
log_dir = os.getenv("LOG_DIR")
if log_dir is not None:
    log_dir = Path(log_dir) / datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")

# Create the singleton instance
logger_manager = LoggerManager(anchor=log_dir)



