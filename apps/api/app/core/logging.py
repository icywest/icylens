import logging

from app.core.config import LogLevel

LOGGER_NAME = "icylens"
HANDLER_NAME = "icylens.console"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging(log_level: LogLevel) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(log_level)
    logger.propagate = False

    handler = next(
        (item for item in logger.handlers if item.get_name() == HANDLER_NAME),
        None,
    )
    if handler is None:
        handler = logging.StreamHandler()
        handler.set_name(HANDLER_NAME)
        logger.addHandler(handler)

    handler.setLevel(log_level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    return logger
