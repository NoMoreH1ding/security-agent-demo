import time
from loguru import logger


def timer(start_time, return_code):
    duration = time.time() - start_time
    logger.info(
        f"[TOOL DONE] Execution finished in {duration:.2f}s with return code {return_code}"
    )
