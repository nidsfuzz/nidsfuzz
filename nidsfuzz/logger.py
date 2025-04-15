import inspect
import os.path
import datetime
import sys

from loguru import logger as log

"""
    Example Usage:
    --------
    >>> import logger
    
    >>> logger.debug("This is a debug message.")
    >>> logger.info("This is an info message.")
    >>> logger.warning("This is a warning message.", reason="A")
    >>> logger.warning("This is another message.", reason="A")
    
    >>> # 2024-09-03 21:51:34.255 | DEBUG    | module:function:line - This is a debug message.
    >>> # 2024-09-03 21:51:34.255 | INFO     | module:function:line - This is an info message.
    >>> # 2024-09-03 21:52:44.796 | WARNING  | module:function:line - This is a warning message. [reason: A]
    >>> # 2024-09-03 21:52:44.796 | WARNING  | module:function:line - This is another message. [reason: A]
"""


# define the root log path as the project root directory
LOG_PATH = os.getenv("LOG_DIR", os.path.dirname(os.path.dirname(__file__)))

# create a unique directory for each fuzzing task
uid = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
log_dir = os.path.join(
    LOG_PATH,
    f"logs_{uid}"
)
# os.makedirs(log_dir, exist_ok=True)

# log_formate = "{time:YYYY-MM-DD HH:mm:ss.SSS} | <level>{level:<8}</level> | {file}:{function}:{line} - {message} {extra}"

# configure log handlers in loguru
default_file_handler = {
    'format': '{message}',
    'level': 'DEBUG',
    'rotation': '1 hour',
    'enqueue': True,
    'encoding': 'utf-8',
}
default_console_handler = {
    'format': '{message}',
    'level': 'DEBUG',
    'enqueue': True,
}

# remove default handler
log.remove(0)
# add stderr handler for any log message
log.add(sys.stderr, **default_console_handler)

# ONLY pay attention to the modules defined in the following list
logged_modules = [
    "fuzzer",
    "traffic_injector",
    # "rule_mutator",
    "alert_sanitizer"
]

# Note: (debug usage) This line should be commented in production environment
# print("Executing logger initialization code...... (This should only be seen once)")

def filter_module(module_name):
    def _filter(record):
        log_msg = record["message"]
        module = log_msg.split(" | ", maxsplit=2)[-1].split(":", maxsplit=1)[0].split(".")[0].strip()
        return module == module_name
    return _filter

for logged_module in logged_modules:
    module_handler = default_file_handler.copy()
    log.add(
        os.path.join(log_dir, f"{logged_module}.log"),
        **module_handler,
        filter=filter_module(logged_module)
    )


def log_msg_format(msg: str, level="INFO", **context):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    frame = inspect.currentframe().f_back.f_back
    line = frame.f_lineno
    func = frame.f_code.co_name
    module = frame.f_globals["__name__"]
    formatted_message = f"{timestamp} | {level.upper():<8} | {module}:{func}:{line} - {msg}"
    for k, v in context.items():
        formatted_message += f" [{k}: {v}]"
    return formatted_message


def trace(msg: str, **context):
    msg = log_msg_format(msg, "TRACE", **context)
    log.trace(msg)


def debug(msg: str, **context):
    msg = log_msg_format(msg, "DEBUG", **context)
    log.debug(msg)


def info(msg: str, **context):
    msg = log_msg_format(msg, "INFO", **context)
    log.info(msg)


def success(msg: str, **context):
    msg = log_msg_format(msg, "SUCCESS", **context)
    log.success(msg)


def warning(msg: str, **context):
    msg = log_msg_format(msg, "WARNING", **context)
    log.warning(msg)


def error(msg: str, **context):
    msg = log_msg_format(msg, "ERROR", **context)
    log.error(msg)


def critical(msg: str, **context):
    msg = log_msg_format(msg, "CRITICAL", **context)
    log.critical(msg)

