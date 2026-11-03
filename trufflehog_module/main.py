import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from mobsec_modules_library.external import ExternalModule, make_finding

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

os.environ.setdefault("MODULE_ID", "trufflehog-scanner")
os.environ.setdefault("MODULE_BASE_URL", "http://trufflehog_scanner:8083")


class TruffleHogModule(ExternalModule):
    async def scan(self, work_dir: Path, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = work_dir
        if task.get("file_name"):
            target = (work_dir / task["file_name"]).resolve()
            if not target.is_relative_to(work_dir.resolve()):
                raise ValueError(f"file_name escapes work dir: {task['file_name']}")

        logger.info("Running TruffleHog scan on: %s", target)
        process = await asyncio.create_subprocess_exec(
            "trufflehog", "filesystem", "--json", "--no-update", str(target),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode not in (0, 1):
            raise RuntimeError(
                f"TruffleHog failed with code {process.returncode}: "
                f"{stderr.decode('utf-8', 'replace')}"
            )

        findings: List[Dict[str, Any]] = []
        for line in stdout.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse TruffleHog output line: %s", e)
                continue
            if not isinstance(result, dict) or "SourceMetadata" not in result:
                continue

            fs = result["SourceMetadata"].get("Data", {}).get("Filesystem", {})
            file_name = fs.get("file", "")
            line_number = fs.get("line", 0)
            raw_secret = result.get("Raw", "No raw value available")
            detector = result.get("DetectorName", "Unknown")

            message = f"Found {detector} secret in {os.path.basename(file_name)}"
            if result.get("DetectorDescription"):
                message += f": {result['DetectorDescription']}"

            findings.append(
                make_finding(
                    rule_id="secret_detection",
                    name=f"Found {detector} Secret",
                    message=message,
                    severity="ERROR",
                    file=os.path.basename(file_name),
                    path=file_name,
                    start_line=line_number,
                    code=raw_secret,
                    description=f"Detected {detector} secret pattern",
                    detector=detector,
                    entropy=result.get("Entropy", 0),
                    category="secret",
                    secret_value=raw_secret,
                    detector_type=result.get("DetectorType", ""),
                    verified=result.get("Verified", False),
                    extra_data=result.get("ExtraData", {}),
                )
            )
        return findings


module = TruffleHogModule(ui_component="TrufflehogReport.vue")
app = module.create_app()

if __name__ == "__main__":
    module.run()
