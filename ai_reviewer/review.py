import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import quote

from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

REPORT_JSON = "review_report.json"
REPORT_MD = "review_report.md"

COMMENT_MARKER = "<!-- AI_SECURITY_REVIEW_REPORT -->"

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".cpp", ".c", ".h"
}

IGNORED_DIRECTORIES = {
    ".git", ".github", "venv", ".venv",
    "__pycache__", "node_modules"
}

# Never review the AI reviewer using itself.
IGNORED_FILES = {
    "ai_reviewer/review.py",
    "ai_reviewer/review_backup.py"
}

MAX_FILE_SIZE = 200_000
MAX_ATTEMPTS = 4


# --------------------------------------------------
# PYDANTIC SCHEMAS
# --------------------------------------------------

class CodeIssue(BaseModel):
    severity: str
    line: str
    issue: str
    fix: str


class ReviewResponse(BaseModel):
    issues: list[CodeIssue]


# --------------------------------------------------
# GIT / CHANGED FILE DISCOVERY
# --------------------------------------------------

def get_changed_files() -> list[str]:

    base_ref = os.getenv("GITHUB_BASE_REF", "")

    if not base_ref:
        raise RuntimeError("GITHUB_BASE_REF is missing.")

    target = f"origin/{base_ref}...HEAD"

    print(f"Finding changed files using: {target}", flush=True)

    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMRT",
            target
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True
    )

    files = []

    for filename in result.stdout.splitlines():

        filename = filename.strip()

        if not filename:
            continue

        path = Path(filename)

        if filename in IGNORED_FILES:
            print(f"Skipping reviewer file: {filename}", flush=True)
            continue

        if not path.is_file():
            continue

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        if path.stat().st_size > MAX_FILE_SIZE:
            print(f"Skipping oversized file: {filename}", flush=True)
            continue

        files.append(filename)

    return sorted(set(files))


# --------------------------------------------------
# READ SOURCE FILE WITH LINE NUMBERS
# --------------------------------------------------

def get_file_content(filepath: str) -> str:

    lines = Path(filepath).read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    return "\n".join(
        f"{number}: {line}"
        for number, line in enumerate(lines, start=1)
    )


# --------------------------------------------------
# GEMINI MODEL DISCOVERY
# --------------------------------------------------

def get_candidate_models(client: genai.Client) -> list[str]:

    preferred = [
        "gemini-3.5-flash-lite",
        "gemini-3.8-flash",
        "gemini-3.1-pro-preview",
        "gemini-3.8-flash-lite"
    ]

    print("Starting Gemini model discovery...", flush=True)

    available = []

    for model in client.models.list():

        name = (
            getattr(model, "name", "") or ""
        ).replace("models/", "")

        methods = (
            getattr(model, "supported_actions", None)
            or getattr(model, "supported_generation_methods", None)
            or []
        )

        if (
            "generateContent" in methods
            and "gemini" in name.lower()
            and "2.0" not in name
            and "2.5" not in name
            and "embedding" not in name.lower()
            and "image" not in name.lower()
        ):
            available.append(name)

    ordered = [
        name for name in preferred
        if name in available
    ]

    for name in available:

        if name not in ordered and (
            "flash" in name or "pro" in name
        ):
            ordered.append(name)

    if not ordered:
        raise RuntimeError(
            "No supported Gemini generation models were discovered. "
            "Check the API key and available models."
        )

    selected = ordered[:5]

    print(f"Available candidate models: {selected}", flush=True)

    return selected


# --------------------------------------------------
# ANALYZE ONE FILE
# --------------------------------------------------

def analyze_file(
    client: genai.Client,
    filepath: str,
    content: str,
    candidate_models: list[str]
) -> tuple[list[CodeIssue], str]:

    prompt = f"""
You are an expert application security auditor.

Analyze the following source file for genuine, actionable
security vulnerabilities.

FILE: {filepath}

Check for:

1. Buffer overflows
2. Unsafe strcpy, gets and memory operations
3. Format string vulnerabilities
4. OS command injection
5. SQL injection
6. Integer overflows
7. Use-after-free
8. Double-free
9. Path traversal
10. Hardcoded credentials and secrets
11. Insecure file handling
12. Other serious security weaknesses

IMPORTANT RULES:

- Inspect the supplied source code carefully.
- Use the exact line number shown at the start of each line.
- Never invent line numbers.
- Report only genuine vulnerabilities.
- Do not report safe operations as vulnerabilities without
  a concrete explanation of how they can be exploited.
- Do not flag subprocess calls that use an argument list
  with shell=False merely because they use subprocess.
- Do not report a vulnerability that has already been fixed.
- If a previous unsafe operation has been replaced with a
  safe equivalent, recognize the correction.
- Severity must be Critical, High, Medium or Low.
- Provide a practical correction for each finding.

SOURCE CODE:

{content}
"""

    errors = []

    for attempt in range(MAX_ATTEMPTS):

        model = candidate_models[attempt % len(candidate_models)]

        print(
            f"Gemini attempt {attempt + 1}/{MAX_ATTEMPTS}: {model}",
            flush=True
        )

        try:

            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ReviewResponse,
                    temperature=0.1
                )
            )

            if response.parsed is not None:

                parsed = response.parsed

                if getattr(parsed, "issues", None) is not None:
                    return parsed.issues, ""

            raw_text = (response.text or "").strip()

            if raw_text:

                data = json.loads(raw_text)

                issues = [
                    CodeIssue(**item)
                    for item in data.get("issues", [])
                ]

                return issues, ""

            errors.append(f"{model}: Empty response")

        except APIError as error:

            message = (
                f"{model}: API error {error.code}: {error.message}"
            )

            errors.append(message)

            print(message, flush=True)

        except Exception as error:

            message = (
                f"{model}: {type(error).__name__}: {error}"
            )

            errors.append(message)

            print(message, flush=True)

        if attempt < MAX_ATTEMPTS - 1:

            delay = 3 * (attempt + 1)

            print(
                f"Retrying after {delay} seconds...",
                flush=True
            )

            time.sleep(delay)

    return [], (
        "All Gemini attempts failed: " + " | ".join(errors)
    )


# --------------------------------------------------
# LINE NUMBER VALIDATION
# --------------------------------------------------

def parse_line_num(raw_line: str) -> int:

    digits = ""

    for char in str(raw_line):
        if char.isdigit():
            digits += char
        else:
            break

    return int(digits) if digits else 1


# --------------------------------------------------
# GITHUB SOURCE LINKS
# --------------------------------------------------

def get_source_link(
    repo: str,
    sha: str,
    filepath: str,
    line_num: int
) -> str:

    encoded_path = quote(filepath, safe="/")

    return (
        f"https://github.com/{repo}/blob/"
        f"{sha}/{encoded_path}#L{line_num}"
    )


# --------------------------------------------------
# BUILD SECURITY REPORT
# --------------------------------------------------

def create_report(
    results: list[dict],
    repo: str,
    sha: str
) -> tuple[str, str]:

    all_issues = [
        issue
        for result in results
        for issue in result["issues"]
    ]

    review_errors = [
        result for result in results
        if result.get("error")
    ]

    if review_errors:
        status = "ERROR"
    elif all_issues:
        status = "FAILED"
    else:
        status = "PASSED"

    severities = [
        "CRITICAL", "HIGH", "MEDIUM", "LOW"
    ]

    counts = {
        severity: sum(
            issue["severity"].upper() == severity
            for issue in all_issues
        )
        for severity in severities
    }

    report = {
        "status": status,
        "repository": repo,
        "commit": sha,
        "total_issues": len(all_issues),
        "severity_counts": counts,
        "results": results
    }

    Path(REPORT_JSON).write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    lines = [
        COMMENT_MARKER,
        "# AI Security Review",
        "",
        f"**Status:** {status}",
        "",
        f"**Commit reviewed:** `{sha}`",
        "",
        f"**Total findings:** {len(all_issues)}",
        "",
        "## Security Summary",
        "",
        "| Severity | Count |",
        "|---|---:|"
    ]

    for severity, count in counts.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend(["", "## Detected Issues", ""])

    if not all_issues:
        lines.append("No security vulnerabilities detected.")

    for result in results:

        filepath = result["file"]

        if result.get("error"):
            lines.extend([
                f"### Review execution error: {filepath}",
                "",
                result["error"],
                ""
            ])

        for issue in result["issues"]:

            line_num = issue["line_number"]

            link = get_source_link(
                repo,
                sha,
                filepath,
                line_num
            )

            lines.extend([
                f"### {issue['severity'].upper()}: {issue['issue']}",
                "",
                f"**File:** `{filepath}`",
                "",
                f"**Line:** {line_num}",
                "",
                f"**Suggested fix:** {issue['fix']}",
                "",
                f"[REFIX ERRORS - Open affected code]({link})",
                "",
                "---",
                ""
            ])

    lines.extend([
        "",
        "_Generated automatically by the Gemini AI Security Reviewer._"
    ])

    markdown = "\n".join(lines)

    Path(REPORT_MD).write_text(
        markdown,
        encoding="utf-8"
    )

    return status, markdown


# --------------------------------------------------
# PUBLISH OR UPDATE GITHUB PR COMMENT
# --------------------------------------------------

def update_pr_comment(markdown: str) -> None:

    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    pr_number = os.getenv("PR_NUMBER", "")

    if not token or not repo or not pr_number:
        print("PR comment credentials missing.", flush=True)
        return

    api_url = (
        f"https://api.github.com/repos/{repo}"
        f"/issues/{pr_number}/comments?per_page=100"
    )

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json"
    }

    try:

        request = urllib.request.Request(
            api_url,
            headers=headers
        )

        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:

            comments = json.loads(
                response.read().decode("utf-8")
            )

        existing = next(
            (
                comment for comment in comments
                if COMMENT_MARKER in comment.get("body", "")
            ),
            None
        )

        if existing:

            url = (
                f"https://api.github.com/repos/{repo}"
                f"/issues/comments/{existing['id']}"
            )

            method = "PATCH"

            print("Updating existing security report...", flush=True)

        else:

            url = (
                f"https://api.github.com/repos/{repo}"
                f"/issues/{pr_number}/comments"
            )

            method = "POST"

            print("Creating security report comment...", flush=True)

        payload = json.dumps({
            "body": markdown
        }).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=payload,
            headers=headers,
            method=method
        )

        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:

            print(
                f"PR report published: HTTP {response.status}",
                flush=True
            )

    except Exception as error:

        print(
            f"PR report publishing warning: {error}",
            flush=True
        )


# --------------------------------------------------
# GITHUB STEP SUMMARY
# --------------------------------------------------

def write_step_summary(markdown: str) -> None:

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")

    if not summary_path:
        return

    try:

        with open(
            summary_path,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(markdown)

        print("GitHub Actions summary generated.", flush=True)

    except Exception as error:

        print(f"Summary warning: {error}", flush=True)


# --------------------------------------------------
# GITHUB INLINE ANNOTATIONS
# --------------------------------------------------

def escape_command(value: str) -> str:

    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def publish_annotations(results: list[dict]) -> None:

    for result in results:

        filepath = result["file"]

        for issue in result["issues"]:

            severity = issue["severity"].upper()

            level = (
                "warning"
                if severity in {"LOW", "MEDIUM"}
                else "error"
            )

            message = (
                f"[{severity}] {issue['issue']} "
                f"| Fix: {issue['fix']}"
            )

            safe_message = escape_command(message)

            safe_file = (
                escape_command(filepath)
                .replace(",", "%2C")
                .replace(":", "%3A")
            )

            print(
                f"::{level} file={safe_file},"
                f"line={issue['line_number']}::{safe_message}",
                flush=True
            )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main() -> None:

    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        print(
            "::error::GEMINI_API_KEY is missing.",
            flush=True
        )
        sys.exit(1)

    repo = os.getenv("GITHUB_REPOSITORY", "")

    sha = (
        os.getenv("GITHUB_HEAD_SHA", "")
        or os.getenv("GITHUB_SHA", "")
    )

    print("Starting AI security review...", flush=True)

    results = []

    try:

        files = get_changed_files()

        print(f"Changed source files: {files}", flush=True)

        if not files:
            print(
                "No supported changed source files found.",
                flush=True
            )

        else:

            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(
                    timeout=45000
                )
            )

            candidate_models = get_candidate_models(client)

            for filepath in files:

                print(
                    f"\nStarting review: {filepath}",
                    flush=True
                )

                content = get_file_content(filepath)

                if not content.strip():
                    continue

                issues, error = analyze_file(
                    client,
                    filepath,
                    content,
                    candidate_models
                )

                validated_issues = []

                source_line_count = len(
                    Path(filepath).read_text(
                        encoding="utf-8",
                        errors="replace"
                    ).splitlines()
                )

                for issue in issues:

                    line_num = parse_line_num(issue.line)

                    if not 1 <= line_num <= source_line_count:
                        print(
                            f"Ignoring invalid line number: "
                            f"{filepath}:{line_num}",
                            flush=True
                        )
                        continue

                    validated_issues.append({
                        "severity": issue.severity,
                        "line": issue.line,
                        "line_number": line_num,
                        "issue": issue.issue,
                        "fix": issue.fix
                    })

                results.append({
                    "file": filepath,
                    "issues": validated_issues,
                    "error": error
                })

                if error:
                    print(
                        f"Review failed for {filepath}: {error}",
                        flush=True
                    )

                else:
                    print(
                        f"Completed review: {filepath}. "
                        f"Findings: {len(validated_issues)}",
                        flush=True
                    )

        status, markdown = create_report(
            results,
            repo,
            sha
        )

        # Publish the report before failing the check.
        update_pr_comment(markdown)

        write_step_summary(markdown)

        publish_annotations(results)

        total_issues = sum(
            len(result["issues"])
            for result in results
        )

        print("\n--------------------------------", flush=True)
        print(f"SECURITY REVIEW STATUS: {status}", flush=True)
        print(f"TOTAL FINDINGS: {total_issues}", flush=True)
        print("--------------------------------", flush=True)

        if status == "ERROR":
            print(
                "::error::One or more file reviews failed.",
                flush=True
            )
            sys.exit(1)

        if status == "FAILED":
            print(
                "::error::Security vulnerabilities detected.",
                flush=True
            )
            sys.exit(1)

        print(
            "PASSED: No security vulnerabilities detected.",
            flush=True
        )

    except Exception as error:
        print(
            f"::error::Security review execution failed: "
            f"{type(error).__name__}: {error}",
            flush=True
        )
        sys.exit(1)


if __name__ == "__main__":
    main()