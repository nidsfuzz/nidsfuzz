import pathlib
import sys

from loguru import logger

logger.remove()

logger.add(
    sys.stderr,
    level='DEBUG',
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
    colorize=True,
)

def setup_logger(log_path: str):
    log_path = pathlib.Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        log_path,
        level='DEBUG',
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
        rotation="10 MB",
        retention="10 days",
        compression="zip",
        encoding="utf-8",
    )

__all__ = ["logger", "setup_logger"]
