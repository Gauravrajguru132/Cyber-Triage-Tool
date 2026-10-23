import time
import uuid
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=4)

# In-memory tasks store
TASKS_STORE = {}

def create_async_task():
    """Generates and registers a new async triage task ID."""
    task_id = str(uuid.uuid4())
    TASKS_STORE[task_id] = {
        "id": task_id,
        "status": "pending",
        "progress_pct": 0,
        "stage": "Queued for processing",
        "result_inv_id": None,
        "error": None,
        "created_at": time.time()
    }
    return task_id

def update_task_progress(task_id, progress_pct, stage_msg, inv_id=None, error=None):
    """Updates live progress state for a task."""
    if task_id in TASKS_STORE:
        TASKS_STORE[task_id]["progress_pct"] = progress_pct
        TASKS_STORE[task_id]["stage"] = stage_msg
        if inv_id:
            TASKS_STORE[task_id]["result_inv_id"] = inv_id
            TASKS_STORE[task_id]["status"] = "completed"
        if error:
            TASKS_STORE[task_id]["error"] = str(error)
            TASKS_STORE[task_id]["status"] = "failed"
        elif progress_pct < 100 and not inv_id:
            TASKS_STORE[task_id]["status"] = "running"

def get_task_status(task_id):
    """Retrieves current status of task."""
    return TASKS_STORE.get(task_id, {"status": "not_found", "progress_pct": 0})
