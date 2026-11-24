import json
import os
import subprocess
import sys
import time
from pathlib import Path
from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel

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


def get_candidate_models(client: genai.Client) -> list[str]:
    preferred = ["gemini-3.8-flash-lite", "gemini-3.8-flash", "gemini-3.8-pro-preview", "gemini-2.5-flash-lite"]
    try:
        available = []
        for m in client.models.list():
            methods = getattr(m, "supported_actions", None) or getattr(m, "supported_generation_methods", None) or []
            name = (getattr(m, "name", "") or "").replace("models/", "")
            if "generateContent" in methods and "gemini" in name and "embedding" not in name and "image" not in name:
                available.append(name)
        ordered = [m for m in preferred if m in available]
        for m in available:
            if m not in ordered and ("flash" in m or "pro" in m):
                ordered.append(m)
        if ordered:
            return ordered[:5]
    except Exception as e:
        print(f"Model discovery warning: {e}")
    return preferred


def analyze_file(client: genai.Client, filepath: str, code_content: str, candidate_models: list[str]) -> list[CodeIssue]:
    prompt = (
        f"You are an expert application security auditor. Analyze `{filepath}` for all security "
        "vulnerabilities (buffer overflows, gets(), format string bugs, command injection, SQL injection, "
        "integer overflows, use-after-free, double free, path traversal, hardcoded secrets) and critical bugs.\n"
        "Use the exact integer line number shown at the start of each line.\n\n"
        f"```\n{code_content}\n```"
    )

    errors = []
    for attempt in range(4):
        current_model = candidate_models[attempt % len(candidate_models)]
        try:
            response = client.models.generate_content(
                model=current_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ReviewResponse,
                    temperature=0.1,
                ),
            )
            if response.parsed and getattr(response.parsed, "issues", None) is not None:
                return response.parsed.issues

            raw_text = (response.text or "").strip()
            if raw_text:
                data = json.loads(raw_text)
                return [CodeIssue(**item) for item in data.get("issues", [])]

            errors.append(f"{current_model}: empty response")
        except APIError as e:
            msg = f"{current_model} ({e.code}): {e.message}"
            errors.append(msg)
            print(f"[Attempt {attempt + 1}/4] {msg}")
            time.sleep(4 * (attempt + 1))
        except Exception as e:
            msg = f"{current_model} ({type(e).__name__}): {e}"
            errors.append(msg)
            print(f"[Attempt {attempt + 1}/4] {msg}")
            time.sleep(2)

    return [
        CodeIssue(
            severity="ERROR",
            line="1",
            issue="All model attempts failed: " + " | ".join(errors[-2:]),
            fix="Check GEMINI_API_KEY quota/billing in Google AI Studio or re-run job after transient 503 spike.",
        )
    ]


def parse_line_num(raw_line: str) -> int:
    digits = "".join(ch for ch in str(raw_line).split("-")[0] if ch.isdigit())
    return int(digits) if digits else 1


def main() -> None:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("::error::GEMINI_API_KEY secret is missing or empty.")
        sys.exit(1)

    files = get_changed_files()
    client = genai.Client(api_key=api_key)
    candidate_models = get_candidate_models(client)

    repo = os.getenv("GITHUB_REPOSITORY", "")
    sha = os.getenv("GITHUB_SHA", "")
    total_issues = 0

    for filepath in files:
        content = get_file_diff_or_content(filepath)
        if not content.strip():
            continue

        issues = analyze_file(client, filepath, content, candidate_models)
        for item in issues:
            total_issues += 1
            line_num = parse_line_num(item.line)
            msg = f"[{item.severity}] {item.issue} | Fix: {item.fix}".replace("\n", " ")
            # Emits clickable inline error annotation directly on the file & line in GitHub PR
            print(f"::error file={filepath},line={line_num}::{msg}")
            if repo and sha:
                print(f"-> Jump to code: https://github.com/{repo}/blob/{sha}/{filepath}#L{line_num}")

    if total_issues > 0:
        print(f"\nFailed: Found {total_issues} security/code error(s). Click any annotation above to jump directly to the line of code.")
        sys.exit(1)

    print("Passed: No security vulnerabilities or errors found.")


if __name__ == "__main__":
    main()
