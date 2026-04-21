"""Minimal logging setup wrapping the stdlib logger."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "crucible", verbose: bool = False) -> logging.Logger:
    """Return a configured logger.

    Args:
        name: Logger name.
        verbose: If True, set level to DEBUG, otherwise INFO.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)-5s %(name)s: %(message)s",
                          datefmt="%H:%M:%S")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger
