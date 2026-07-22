import subprocess
import logging

logger = logging.getLogger(__name__)


def freeze_and_thaw_zone(zone):
    frozen = False

    try:
        # Step 1: Freeze the zone
        freeze_cmd = ["rndc", "freeze", zone]
        result = subprocess.run(freeze_cmd,capture_output=True,text=True,check=True,timeout=10,)
        frozen = True
        logger.info(f"Freeze successful for zone {zone}: {result.stdout.strip()}")

        # Step 2: Thaw the zone
        thaw_cmd = ["rndc", "thaw", zone]
        result = subprocess.run(thaw_cmd,capture_output=True,text=True,check=True,timeout=10,)
        frozen = False
        logger.info(
            f"Thaw successful for zone {zone}: {result.stdout.strip()}")

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error(
            f"Failed while processing zone {zone}: {str(e)}")

        if frozen:
            try:
                logger.warning(f"Attempting recovery thaw for zone {zone}")
                subprocess.run(["rndc", "thaw", zone],capture_output=True,text=True,check=True,timeout=10,)
                logger.info(f"Recovery thaw successful for zone {zone}")

            except Exception as recovery_error:
                logger.critical(
                    f"Recovery thaw failed for zone {zone}: {recovery_error}. "
                    f"Manual intervention required. Run: rndc thaw {zone}"
                )
                raise RuntimeError(
                    f"Failed to freeze/thaw zone {zone}. "
                    f"Recovery thaw also failed: {recovery_error}. "
                    f"Manual intervention required. Run: rndc thaw {zone}."
                ) from e

        raise RuntimeError(
            f"Failed to freeze/thaw zone {zone}. "
            ) from e
