import logging
import sys
import os

def setup_logging(level=logging.INFO):
    log_dir = "E:/git/bind-api/logs"
    os.makedirs(log_dir, exist_ok=True)  #make the file if it is not exist
    log_file = os.path.join(log_dir, "app.log")
    """Configure application-wide logging."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

logger = logging.getLogger(__name__)