import os
import subprocess
import sys
import time
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel

load_dotenv()

MODEL_NAME = "gemini-2.5-flash"
REPORT_FILE = Path("review_report.md")


class CodeIssue(BaseModel):
    severity: str
    line: str
    issue: str
    fix: str


class ReviewResponse(BaseModel):
    issues: list[CodeIssue]


def get_changed_files() -> list[str]:
    """Return modified/added code files from git diff."""
    try:
        base_ref = os.getenv("GITHUB_BASE_REF")
        diff_target = f"origin/{base_ref}...HEAD" if base_ref else "HEAD~1..HEAD"
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", diff_target],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        files = []

    allowed_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".cpp", ".c"}
    ignored_dirs = {".git", ".github", "venv", ".venv", "__pycache__", "node_modules"}

    valid_files = []
    for f in files:
        path = Path(f)
        if not path.is_file():
            continue
        if any(part in ignored_dirs for part in path.parts):
            continue
        if path.suffix.lower() in allowed_exts:
            valid_files.append(f)

    return valid_files


def get_diff_target() -> str:
    """Determine the exact git diff range for PRs or branch pushes."""
    base_ref = os.getenv("GITHUB_BASE_REF")
    if base_ref:
        return f"origin/{base_ref}...HEAD"

    before_sha = os.getenv("GITHUB_EVENT_BEFORE", "")
    # On brand-new branches, GITHUB_EVENT_BEFORE is all zeros; fall back to HEAD~1..HEAD
    if before_sha and set(before_sha) != {"0"}:
        return f"{before_sha}..HEAD"

    return "HEAD~1..HEAD"


def get_changed_files() -> list[str]:
    """Return modified/added code files from git diff."""
    try:
        diff_target = get_diff_target()
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", diff_target],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        files = []

    allowed_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".cpp", ".c"}
    ignored_dirs = {".git", ".github", "venv", ".venv", "__pycache__", "node_modules"}

    valid_files = []
    for f in files:
        path = Path(f)
        if not path.is_file():
            continue
        if any(part in ignored_dirs for part in path.parts):
            continue
        if path.suffix.lower() in allowed_exts:
            valid_files.append(f)

    return valid_files


def get_file_diff_or_content(filepath: str) -> str:
    """Return full numbered content for newly added files, or unified diff for modified files."""
    try:
        diff_target = get_diff_target()
        status_res = subprocess.run(
            ["git", "diff", "--name-status", diff_target, "--", filepath],
            capture_output=True,
            text=True,
            check=True,
        )
        # If the file is newly added ('A'), send full numbered content so Gemini sees exact lines
        if status_res.stdout.startswith("A\t"):
            raw_lines = Path(filepath).read_text(encoding="utf-8", errors="ignore").splitlines()
            return "\n".join(f"{idx}: {line}" for idx, line in enumerate(raw_lines, start=1))

        result = subprocess.run(
            ["git", "diff", diff_target, "--", filepath],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            return result.stdout
    except subprocess.CalledProcessError:
        pass

    return Path(filepath).read_text(encoding="utf-8", errors="ignore")