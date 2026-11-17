import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c"
}

IGNORED_DIRS = {
    ".git", ".github", "venv", ".venv", "__pycache__",
    "node_modules", "dist", "build", ".idea", ".vscode"
}

def _get_changed_files_from_git(root_path: Path) -> Optional[List[Path]]:
    """Returns changed files against the PR base branch in GitHub Actions, or None if not in a PR."""
    base_ref = os.getenv("GITHUB_BASE_REF")
    if not base_ref:
        return None

    try:
        subprocess.run(
            ["git", "fetch", "--no-tags", "--depth=1", "origin", base_ref],
            cwd=root_path,
            check=True,
            capture_output=True,
            text=True,
        )
        diff_output = subprocess.check_output(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", f"origin/{base_ref}...HEAD"],
            cwd=root_path,
            text=True,
        )
        return [root_path / line.strip() for line in diff_output.splitlines() if line.strip()]
    except subprocess.CalledProcessError as exc:
        print(f"⚠️ Could not compute git diff ({exc}); falling back to full repository scan.")
        return None

def _format_file(file_path: Path, root_path: Path) -> Optional[tuple[str, str]]:
    if not file_path.is_file() or file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return None

    try:
        rel_path = file_path.relative_to(root_path).as_posix()
    except ValueError:
        return None

    if rel_path.startswith("ai_reviewer/"):
        return None

    if any(part in IGNORED_DIRS for part in Path(rel_path).parts):
        return None

    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None

    if not content.strip():
        return None

    numbered_lines = [
        f"{idx}: {line}"
        for idx, line in enumerate(content.splitlines(), start=1)
    ]
    return rel_path, "\n".join(numbered_lines)

def scan_repository(root_dir: str = ".") -> Dict[str, str]:
    """
    Scans PR-changed files when running in a GitHub Pull Request,
    otherwise scans all supported files in the repository.
    """
    scanned_files: Dict[str, str] = {}
    root_path = Path(root_dir).resolve()

    changed_files = _get_changed_files_from_git(root_path)
    if changed_files is not None:
        print(f"🔀 PR mode active: checking {len(changed_files)} changed path(s)...")
        for file_path in sorted(changed_files):
            formatted = _format_file(file_path, root_path)
            if formatted:
                scanned_files[formatted[0]] = formatted[1]
        return scanned_files

    for current_root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for filename in sorted(files):
            formatted = _format_file(Path(current_root) / filename, root_path)
            if formatted:
                scanned_files[formatted[0]] = formatted[1]

    return scanned_files