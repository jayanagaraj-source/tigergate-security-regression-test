"""Archive extraction cases for Python (trailofbits tarfile-extractall-traversal)."""
import tarfile


def extract_upload(archive_path, dest):
    with tarfile.open(archive_path) as tar:  # PY-ZIP-TP-001
        tar.extractall(dest)


def extract_filtered(archive_path, dest):
    with tarfile.open(archive_path) as tar:  # PY-ZIP-TN-001
        safe = [m for m in tar.getmembers() if not m.name.startswith(("/", "..")) and ".." not in m.name]
        tar.extractall(dest, members=safe)


def extract_data_filter(archive_path, dest):
    with tarfile.open(archive_path) as tar:  # PY-ZIP-TN-002
        tar.extractall(dest, filter="data")
