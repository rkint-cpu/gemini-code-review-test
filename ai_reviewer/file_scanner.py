import os
from pathlib import Path
from typing import Dict

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c"
}

IGNORED_DIRS = {
    ".git", ".github", "venv", ".venv", "__pycache__",
    "node_modules", "dist", "build", ".idea", ".vscode"
}

def scan_repository(root_dir: str = ".") -> Dict[str, str]:
    """
    Scans the repository for supported code files and returns a dictionary
    mapping relative file paths to their line-numbered contents.
    """
    scanned_files: Dict[str, str] = {}
    root_path = Path(root_dir).resolve()

    for current_root, dirs, files in os.walk(root_path):
        # Prune ignored directories in-place so os.walk skips them
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for filename in sorted(files):
            file_path = Path(current_root) / filename
            if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue

            rel_path = file_path.relative_to(root_path).as_posix()

            # Skip reviewing the reviewer's own source code
            if rel_path.startswith("ai_reviewer/"):
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

            if not content.strip():
                continue

            numbered_lines = [
                f"{idx}: {line}"
                for idx, line in enumerate(content.splitlines(), start=1)
            ]
            scanned_files[rel_path] = "\n".join(numbered_lines)

    return scanned_files