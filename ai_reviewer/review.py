import json
import os
import subprocess
import time
from pathlib import Path
from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel

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
    diff_candidates = []
    base_ref = os.getenv("GITHUB_BASE_REF")
    if base_ref:
        diff_candidates.append(f"origin/{base_ref}...HEAD")

    before_sha = os.getenv("GITHUB_EVENT_BEFORE", "")
    if before_sha and set(before_sha) != {"0"}:
        diff_candidates.append(f"{before_sha}..HEAD")

    diff_candidates.extend(["origin/main...HEAD", "HEAD~1..HEAD"])

    files = []
    for target in diff_candidates:
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMRT", target],
                capture_output=True,
                text=True,
                check=True,
            )
            found = [f.strip() for f in result.stdout.splitlines() if f.strip()]
            if found:
                files = found
                break
        except subprocess.CalledProcessError:
            continue

    allowed_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".cpp", ".c", ".h"}
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

    if not valid_files:
        for ext in ("*.c", "*.cpp"):
            for p in sorted(Path(".").glob(ext)):
                if p.is_file():
                    valid_files.append(str(p))

    return valid_files


def get_file_diff_or_content(filepath: str) -> str:
    raw_lines = Path(filepath).read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(f"{idx}: {line}" for idx, line in enumerate(raw_lines, start=1))


def analyze_file(client: genai.Client, filepath: str, code_content: str) -> list[CodeIssue]:
    prompt = (
        f"You are an expert application security auditor. Analyze `{filepath}` for all security "
        "vulnerabilities (buffer overflows, gets(), format string bugs, command injection, SQL injection, "
        "integer overflows, use-after-free, double free, path traversal, hardcoded secrets) and critical bugs.\n"
        "Use the exact line numbers shown at the start of each line.\n\n"
        f"```\n{code_content}\n```"
    )

    last_err = ""
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ReviewResponse,
                    temperature=0.1,
                ),
            )
            if response.parsed and getattr(response.parsed, "issues", None) is not None:
                return response.parsed.issues

            # Fallback if response.parsed is None: parse raw JSON text directly
            raw_text = (response.text or "").strip()
            if raw_text:
                data = json.loads(raw_text)
                return [CodeIssue(**item) for item in data.get("issues", [])]

            last_err = "Gemini returned an empty response (check safety filter or API quota)."
        except APIError as e:
            last_err = f"Gemini APIError ({e.code}): {e.message}"
            print(f"[Attempt {attempt + 1}/3] {last_err}")
            time.sleep(2)
        except Exception as e:
            last_err = f"Unexpected error: {type(e).__name__}: {e}"
            print(f"[Attempt {attempt + 1}/3] {last_err}")
            break

    return [
        CodeIssue(
            severity="ERROR",
            line="API",
            issue=last_err or "Unknown Gemini failure",
            fix="Verify GEMINI_API_KEY in Repo Settings -> Secrets -> Actions and check billing/quota.",
        )
    ]


def main() -> None:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        REPORT_FILE.write_text(
            "## AI Code Review Report\n\n"
            "| Severity | Line | Issue | Suggested Fix |\n| :--- | :--- | :--- | :--- |\n"
            "| **ERROR** | `ENV` | `GEMINI_API_KEY` secret is missing or empty. | Add `GEMINI_API_KEY` in Settings -> Secrets and variables -> Actions. |\n",
            encoding="utf-8",
        )
        return

    files = get_changed_files()
    print(f"Reviewing files: {files}")
    client = genai.Client(api_key=api_key)

    commit_sha = os.getenv("GITHUB_SHA", "local")[:7]
    report_sections = [
        "<!-- AI-CODE-REVIEW-STICKY -->\n",
        f"## AI Code Review Report (Latest Commit: `{commit_sha}`)\n",
    ]
    total_issues = 0

    for filepath in files:
        content = get_file_diff_or_content(filepath)
        if not content.strip():
            continue

        issues = analyze_file(client, filepath, content)
        total_issues += len(issues)

        report_sections.append(f"### `{filepath}`\n")
        if not issues:
            report_sections.append("✅ No security vulnerabilities or critical bugs detected.\n")
        else:
            report_sections.append("| Severity | Line | Issue | Suggested Fix |\n")
            report_sections.append("| :--- | :--- | :--- | :--- |\n")
            for item in issues:
                sev = item.severity.replace("|", "\\|").strip()
                line = item.line.replace("|", "\\|").strip()
                desc = item.issue.replace("|", "\\|").replace("\n", " ").strip()
                fix = item.fix.replace("|", "\\|").replace("\n", " ").strip()
                report_sections.append(f"| **{sev}** | `{line}` | {desc} | {fix} |\n")
        report_sections.append("\n")

    REPORT_FILE.write_text("".join(report_sections), encoding="utf-8")
    print(f"Review complete. Found {total_issues} issue(s). Wrote {REPORT_FILE}.")


if __name__ == "__main__":
    main()
