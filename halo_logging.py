"""
Shared emoji-annotated logging for HALO components.

A single formatter and logger factory used by the agent loop (and available
to any other component) so the console/file logging style is defined once.
"""

import logging
from datetime import datetime


class EmojiFormatter(logging.Formatter):
    ICONS = {
        "SCAN":    "🔍",
        "ATTACK":  "⚔️ ",
        "SUCCESS": "🎉😄",
        "FAIL":    "😤💀",
        "ERROR":   "😭🔥",
        "TOOL":    "✅👍",
        "MEMORY":  "🧠",
        "MODEL":   "🤖",
        "CHAIN":   "🔗",
        "REPORT":  "📝",
        "ENGAGE":  "💣",
        "GOAL":    "🎯",
        "START":   "🚀",
        "FILE":    "📁",
        "WEB":     "🌐",
        "CREDS":   "🔑",
    }

    def format(self, record):
        time = datetime.now().strftime("%H:%M:%S")
        msg = record.getMessage()
        icon = "ℹ️ "
        for key, emoji in self.ICONS.items():
            if f"[{key}]" in msg:
                icon = emoji
                msg = msg.replace(f"[{key}]", "").strip()
                break
        if record.levelno == logging.WARNING:
            icon = "😤💀"
        if record.levelno == logging.ERROR:
            icon = "😭🔥"
        return f"[{time}] {icon}  {msg}"


def setup_logger(name: str, log_file: str) -> logging.Logger:
    """Return a logger that writes emoji-formatted lines to both file and stream."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    fmt = EmojiFormatter()
    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger
