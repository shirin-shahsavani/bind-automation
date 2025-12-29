import subprocess
import logging

logger = logging.getLogger(__name__)

def run_command(zone):
    try:
        # TODO: what if one of the commands results in error?
        # Step 1: Freeze the zone
        freeze_cmd = ["rndc", "freeze", zone]
        result1 = subprocess.run(freeze_cmd, capture_output=True, text=True, check=True)
        logger.info(f"Freeze successful for zone {zone}: {result1.stdout.strip()}")

        # Step 2: Thaw the zone
        thaw_cmd = ["rndc", "thaw", zone]
        result2 = subprocess.run(thaw_cmd, capture_output=True, text=True, check=True)
        logger.info(f"Thaw successful for zone {zone}: {result2.stdout.strip()}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{' '.join(e.cmd)}' failed with code {e.returncode}")
        logger.error(f"stderr: {e.stderr.strip()}")
        raise RuntimeError(f"Failed to run command on zone {zone}: {e.stderr.strip()}")
