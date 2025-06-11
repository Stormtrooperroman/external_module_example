import os
import json
import yaml
import logging
import asyncio
import redis
import shutil
import tarfile
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import httpx
import uvicorn
from contextlib import asynccontextmanager

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

# Environment configuration
MOBSEC_API_URL = os.getenv("MOBSEC_API_URL", "http://backend:8000/api/v1")
MODULE_ID = os.getenv("MODULE_ID", "trufflehog-scanner")
MODULE_BASE_URL = os.getenv("MODULE_BASE_URL", "http://trufflehog_scanner:8080")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

TEMP_DIR = Path("/tmp/trufflehog_module")
TEMP_DIR.mkdir(exist_ok=True, parents=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events"""
    # Startup
    logger.info(f"TruffleHog External Module started with ID: {MODULE_ID}")
    logger.info(f"Configuration: {CONFIG}")
    
    # Start task processor
    loop = asyncio.get_event_loop()
    loop.create_task(start_task_processor())
    
    # Let FastAPI finish its startup
    await asyncio.sleep(1)  # Give FastAPI a moment to set up routes
    
    # Register with backend
    await register_module()
    
    yield
    
    # Shutdown logic (if needed)
    logger.info("Shutting down TruffleHog External Module")

app = FastAPI(lifespan=lifespan)
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# Data models
class OperationRequest(BaseModel):
    task_id: str
    chain_task_id: Optional[str] = None
    data: Dict[str, Any]
    file_hash: Optional[str] = None

class OperationResponse(BaseModel):
    status: str
    data: Dict[str, Any]

class ScanResult(BaseModel):
    status: str = "success"
    results: List[Dict[str, Any]] = []

# UI Component endpoint
@app.get("/ui-component")
async def get_ui_component():
    """Return the Vue component file content for the module's custom UI."""
    try:
        vue_file_path = Path("TrufflehogReport.vue")
        if not vue_file_path.exists():
            raise HTTPException(status_code=404, detail="UI component file not found")
            
        content = vue_file_path.read_text()
        return {
            "component_name": "TrufflehogReport",
            "component_content": content
        }
    except Exception as e:
        logger.error(f"Error reading UI component: {e}")
        raise HTTPException(status_code=500, detail=f"Error reading UI component: {str(e)}")

# Module registration and heartbeat
async def register_module():
    """Register module with the main application"""
    registration_data = {
        "module_id": MODULE_ID,
        "base_url": MODULE_BASE_URL,
        "config": {
            "name": CONFIG["name"],
            "version": CONFIG["version"],
            "description": CONFIG["description"],
            "input_formats": CONFIG["input_formats"],
            "has_custom_ui": True,
            "ui_component": {
                "name": "TrufflehogReport",
                "endpoint": f"{MODULE_BASE_URL}/ui-component"
            }
        },
        "healthcheck_url": f"{MODULE_BASE_URL}/health",
        "status": "active"  # Explicitly set status
    }
    
    max_retries = 3
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient() as client:
                logger.info(f"Attempting to register module with data: {registration_data}")
                response = await client.post(
                    f"{MOBSEC_API_URL}/external-modules/register",
                    json=registration_data,
                    timeout=30.0  # Add explicit timeout
                )
                
                if response.status_code == 200:
                    logger.info(f"Module {MODULE_ID} successfully registered")
                    logger.info(f"Registration response: {response.text}")
                    return
                else:
                    logger.error(f"Module registration error: Status {response.status_code}, Response: {response.text}")
                    
        except Exception as e:
            logger.error(f"Module registration error: {e}")
            
        if attempt < max_retries - 1:
            logger.info(f"Registration attempt {attempt + 1} failed. Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)
    
    logger.error("Failed to register module after all attempts")

# Task processing functions
async def process_task(task_id: str):
    """Process a task from Redis queue"""
    try:
        task_data_str = redis_client.get(f"task:{task_id}")
        if not task_data_str:
            logger.error(f"Task data not found for task {task_id}")
            return
        
        task_data = json.loads(task_data_str)
        file_hash = task_data.get("file_hash")
        
        if not file_hash:
            logger.error(f"No file_hash in task data for task {task_id}")
            return
            
        logger.info(f"Processing task {task_id} for file: {file_hash}")
        
        result = await process_files(file_hash, task_data, task_id)
        
        if not result:
            logger.error(f"Empty scan results for task {task_id}")
            formatted_result = {
                "status": "error",
                "error": "No scan results were produced",
                "results": []
            }
        else:
            # Check if there was an error in processing
            if result.get("status") == "error":
                formatted_result = {
                    "status": "error",
                    "error": result.get("error", "Unknown error occurred"),
                    "results": []
                }
            else:
                # Extract findings from scan result
                findings = result.get("scan_result", {}).get("results", [])
                formatted_result = {
                    "status": "success",
                    "results": findings
                }
                
                logger.info(f"Found {len(findings)} secrets in task {task_id}")
                
                for i, finding in enumerate(findings[:3]):
                    logger.info(f"Finding {i+1}: {json.dumps(finding)}")
        
        # Store results in Redis using file_hash
        result_key = f"result:{MODULE_ID}:{file_hash}"
        redis_client.set(result_key, json.dumps(formatted_result))
        logger.info(f"Stored results in Redis for file {file_hash}")
                    
    except Exception as e:
        logger.error(f"Error processing task {task_id}: {e}")
        try:
            error_result = {
                "status": "error",
                "error": str(e),
                "results": []
            }
            # Store error result in Redis
            result_key = f"result:{MODULE_ID}:{file_hash}"
            redis_client.set(result_key, json.dumps(error_result))
            

        except Exception as report_error:
            logger.error(f"Failed to store error in Redis for task {task_id}: {report_error}")

async def start_task_processor():
    """Start the task processing loop"""
    logger.info(f"Starting task processor for module {MODULE_ID}")
    while True:
        try:
            queue_key = f"module:{MODULE_ID}:queue"
            task_id = redis_client.lpop(queue_key)
            
            if task_id:
                await process_task(task_id)
            else:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Error in task processor: {e}")
            await asyncio.sleep(5)

# Scanner functions
async def run_trufflehog_scan(directory_path: str, task_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Run TruffleHog to scan directory for secrets"""
    if task_data and task_data.get("file_name"):
        directory_path = os.path.join(Path(directory_path), task_data["file_name"])
    else:
        directory_path = str(Path(directory_path))
        
    logger.info(f"Running TruffleHog scan on: {directory_path}")
    try:
        cmd = [
            "trufflehog",
            "filesystem",
            "--json",
            "--no-update",
            directory_path
        ]
        process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0 and process.returncode != 1:
            stderr_str = stderr.decode('utf-8')
            logger.error(f"TruffleHog failed: {stderr_str}")
            return {
                "status": "error",
                "error": f"TruffleHog failed with code {process.returncode}: {stderr_str}"
            }

        findings = []
        stdout_str = stdout.decode('utf-8')
        for line in stdout_str.strip().split('\n'):
            line = line.strip()
            if line:
                try:
                    result = json.loads(line)
                    if isinstance(result, dict):
                        if 'SourceMetadata' not in result:
                            continue
                            
                        source_data = result.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {})
                        file_name = source_data.get('file', '')
                        line_number = source_data.get('line', 0)
                        
                        raw_secret = result.get('Raw', 'No raw value available')
                        detector_name = result.get('DetectorName', 'Unknown')
                        
                        message = f"Found {detector_name} secret in {os.path.basename(file_name)}"
                        if result.get('DetectorDescription'):
                            message += f": {result.get('DetectorDescription')}"
                        
                        finding = {
                            "rule_id": "secret_detection",
                            "name": f"Found {detector_name} Secret",
                            "message": message,
                            "severity": "ERROR",
                            "location": {
                                "file": os.path.basename(file_name),
                                "path": file_name,
                                "start_line": line_number,
                                "end_line": line_number,
                                "code": raw_secret
                            },
                            "metadata": {
                                "description": f"Detected {detector_name} secret pattern",
                                "detector": detector_name,
                                "entropy": result.get('Entropy', 0),
                                "category": "secret",
                                "secret_value": raw_secret,
                                "detector_type": result.get('DetectorType', ''),
                                "verified": result.get('Verified', False),
                                "extra_data": result.get('ExtraData', {})
                            }
                        }
                        findings.append(finding)
                        logger.info(f"Added finding: {file_name}:{line_number} - {detector_name}")
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse TruffleHog output line: {line}, error: {e}")
                except Exception as e:
                    logger.error(f"Error processing finding: {str(e)}")
        
        logger.info(f"Total findings: {len(findings)}")
        
        return {
            "status": "success",
            "results": findings
        }
    
    except Exception as e:
        logger.error(f"Error running TruffleHog: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }

async def process_files(file_hash: str, task_data: Dict[str, Any], task_id: str) -> Dict[str, Any]:
    """Process files via the backend API for scanning"""
    work_dir = TEMP_DIR / f"scan_{task_id}"
    try:
        work_dir.mkdir(exist_ok=True, parents=True)
        logger.info(f"Created work directory for API: {work_dir}")
        
        file_ids = [file_hash]
        logger.info(f"Requesting files from backend API for file_hash: {file_hash}")
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"{MOBSEC_API_URL}/external-modules/{MODULE_ID}/files",
                    params={"file_ids": file_ids}
                )
                
                if response.status_code != 200:
                    logger.error(f"API error: {response.status_code}, {response.text}")
                    return {
                        "status": "error",
                        "error": f"API error: {response.status_code}, {response.text}"
                    }
                
                tar_path = work_dir / "files.tar.gz"
                with open(tar_path, "wb") as f:
                    f.write(response.content)
                logger.info(f"Saved TAR archive from API to: {tar_path}")
                
                try:
                    try:
                        with tarfile.open(tar_path, "r:gz") as tar_ref:
                            tar_ref.extractall(work_dir)
                            logger.info(f"Extracted files to: {work_dir}")
                    except tarfile.ReadError:
                        logger.error("Received file is not a valid TAR archive")
                        return {
                            "status": "error",
                            "error": "Received file is not a valid TAR archive"
                        }
                    except Exception as e:
                        logger.error(f"Error extracting TAR archive: {str(e)}")
                        return {
                            "status": "error",
                            "error": f"Error extracting TAR archive: {str(e)}"
                        }
                    finally:
                        if tar_path.exists():
                            tar_path.unlink()
                            logger.info(f"Removed TAR archive: {tar_path}")
                    
                    logger.info(f"Scanning directory: {work_dir}")
                    try:
                        scan_result = await run_trufflehog_scan(
                            directory_path=str(work_dir),
                            task_data=task_data
                        )
                        
                        if scan_result.get("status") == "error":
                            return scan_result
                        
                        return {
                            "status": "success",
                            "scan_result": {
                                "status": "success",
                                "results": scan_result.get("results", [])
                            }
                        }
                    except Exception as e:
                        logger.error(f"Error in main scan: {str(e)}")
                        return {
                            "status": "error",
                            "error": f"Error in main scan: {str(e)}"
                        }
                    
                except Exception as e:
                    return {
                        "status": "error",
                        "error": f"Error processing files: {str(e)}"
                    }
                
        except (httpx.ReadTimeout, httpx.ConnectTimeout) as e:
            logger.error(f"API request timed out: {str(e)}")
            return {
                "status": "error",
                "error": f"API request timed out: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Error in API request: {str(e)}")
            return {
                "status": "error",
                "error": f"API error: {str(e)}"
            }
    
    except Exception as e:
        logger.error(f"Error in API processing: {str(e)}")
        return {
            "status": "error",
            "error": f"Processing error: {str(e)}"
        }
    finally:
        try:
            if work_dir.exists():
                shutil.rmtree(work_dir, ignore_errors=True)
                logger.info(f"Cleaned up work directory: {work_dir}")
        except Exception as cleanup_error:
            logger.error(f"Error cleaning up work directory: {str(cleanup_error)}")

# API endpoints
@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/operations/process", response_model=OperationResponse)
async def process_operation(request: OperationRequest, background_tasks: BackgroundTasks):
    """Process scan request by adding task to Redis queue"""
    try:
        task_id = request.task_id
        file_hash = request.file_hash
        task_data = request.data
        
        if not file_hash:
            raise HTTPException(status_code=400, detail="Missing file_hash parameter")
        
        redis_client.set(
            f"task:{task_id}",
            json.dumps({
                "file_hash": file_hash,
                "folder_path": task_data.get("folder_path", ""),
            }),
            ex=3600
        )
        
        queue_key = f"module:{MODULE_ID}:queue"
        redis_client.rpush(queue_key, task_id)
        
        logger.info(f"Task {task_id} added to queue for file {file_hash}")
        
        return OperationResponse(
            status="success",
            data={"task_id": task_id, "message": "Task added to queue"}
        )
    
    except Exception as e:
        logger.error(f"Error processing operation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e)
            }
        )

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True) 