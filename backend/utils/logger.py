import logging
from logging.handlers import RotatingFileHandler
import os

# Make a logs directory if it doesn't exist
if not os.path.exists("logs"):
    os.mkdir("logs")

# Create a logger
logger = logging.getLogger("anomaly_logger")
logger.setLevel(logging.DEBUG)  # Capture all severity levels

# Create a rotating file handler
log_file = "logs/anomaly.log"
handler = RotatingFileHandler(log_file, maxBytes=500000, backupCount=5)
handler.setLevel(logging.DEBUG)

# Create a log format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(handler)
