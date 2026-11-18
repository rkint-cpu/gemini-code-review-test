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


def get_file_diff_or_content(filepath: str) -> str:
    """Return the git diff for the file if available, otherwise full content."""
    try:
        base_ref = os.getenv("GITHUB_BASE_REF")
        diff_target = f"origin/{base_ref}...HEAD" if base_ref else "HEAD~1..HEAD"
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


def analyze_code(client: genai.Client, filepath: str, code_snippet: str) -> list[CodeIssue]:
    """Send code/diff to Gemini and parse structured Pydantic issues."""
    prompt = f"""You are a senior security and software engineer reviewing a pull request.
Analyze the following git diff / code from `{filepath}` for security vulnerabilities, bugs, and performance issues.
Ignore minor stylistic nitpicks. Focus ONLY on real defects.
Use severity values: CRITICAL, HIGH, MEDIUM, or LOW.
If no issues are found, return an empty list of issues.

Code / Diff for `{filepath}`:
---
{code_snippet[:12000]}
---"""

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                    response_schema=ReviewResponse,
                ),
            )
            if response.parsed:
                return response.parsed.issues
            return []
        except APIError as e:
            if attempt < 2:
                wait = 2 ** (attempt + 1)
                print(f"Gemini API transient/rate-limit error on {filepath}, retrying in {wait}s: {e}")
                time.sleep(wait)
            else:
                print(f"Failed to analyze {filepath} after retries: {e}")
                return []
        except Exception as e:
            print(f"Unexpected error analyzing {filepath}: {e}")
            return []

    return []


def generate_markdown_report(findings: dict[str, list[CodeIssue]]) -> str:
    """Format findings into a clean Markdown table for GitHub PR comments."""
    lines = ["## 🤖 AI Code Review Report\n"]
    total_issues = sum(len(items) for items in findings.values())

    if total_issues == 0:
        lines.append("✅ **No security, bug, or performance issues detected in the modified files.**")
        return "\n".join(lines)

    lines.append(f"Found **{total_issues}** issue(s) across **{len(findings)}** file(s):\n")
    lines.append("| File | Severity | Line | Issue | Recommended Fix |")
    lines.append("| :--- | :--- | :--- | :--- | :--- |")

    for filepath, issues in findings.items():
        for item in issues:
            sev = item.severity.upper()
            line = str(item.line or "-").replace("|", "\\|")
            desc = str(item.issue).replace("|", "\\|").replace("\n", " ")
            fix = str(item.fix).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{filepath}` | **{sev}** | {line} | {desc} | {fix} |")

    return "\n".join(lines)


def main() -> int:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable is not set.", file=sys.stderr)
        return 1

    client = genai.Client(api_key=api_key)

    files = get_changed_files()
    if not files:
        print("No modified code files detected to review.")
        REPORT_FILE.write_text(
            "## 🤖 AI Code Review Report\n\n✅ **No modified code files to review.**\n",
            encoding="utf-8",
        )
        return 0

    print(f"Reviewing {len(files)} file(s): {', '.join(files)}")
    all_findings: dict[str, list[CodeIssue]] = {}

    for filepath in files:
        content = get_file_diff_or_content(filepath)
        issues = analyze_code(client, filepath, content)
        if issues:
            all_findings[filepath] = issues

    report = generate_markdown_report(all_findings)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Review complete. Report written to {REPORT_FILE}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())