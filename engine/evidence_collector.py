import os
import hashlib
from datetime import datetime

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest()
    }

def collect_evidence_metadata(file_path, original_filename=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    stats = os.stat(file_path)
    file_size = stats.st_size
    filename = original_filename or os.path.basename(file_path)
    ext = os.path.splitext(filename)[1].lower().replace(".", "") or "unknown"
    hashes = calculate_hashes(file_path)

    return {
        "original_filename": filename,
        "stored_filename": os.path.basename(file_path),
        "file_path": file_path,
        "file_size": file_size,
        "file_type": ext.upper(),
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "created_time": datetime.fromtimestamp(stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "modified_time": datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    }

def read_file_safely(file_path, max_bytes=10 * 1024 * 1024):
    """Reads text file safely with multiple encoding fallbacks and size limits."""
    with open(file_path, "rb") as f:
        raw_bytes = f.read(max_bytes)

    for enc in ["utf-8", "utf-16", "cp1252", "latin-1", "ascii"]:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    return raw_bytes.decode("utf-8", errors="ignore")
