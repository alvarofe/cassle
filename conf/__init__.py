from config import DEBUG
import logging


if DEBUG:
    debug_logger = logging.getLogger("debug")
else:
    debug_logger = logging.getLogger("null")

