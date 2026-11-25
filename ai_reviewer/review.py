import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import quote

from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel


REPORT_JSON = "review_report.json"
REPORT_MD = "review_report.md"
COMMENT_MARKER = "<!-- AI_SECURITY_REVIEW_REPORT -->"


class CodeIssue(BaseModel):
    severity: str
    line: str
    issue: str
    fix: str


class ReviewResponse(BaseModel):
    issues: list[CodeIssue]


def get_changed_files() -> list[str]:
    base_ref = os.getenv("GITHUB_BASE_REF", "")
    candidates = []

    if base_ref:
        candidates.append(f"origin/{base_ref}...HEAD")

    candidates.append("HEAD~1..HEAD")

    allowed_exts = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rs", ".cpp", ".c", ".h"
    }

    ignored_dirs = {
        ".git", ".github", "venv", ".venv",
        "__pycache__", "node_modules"
    }

    for target in candidates:
        try:
            result = subprocess.run(
                [
                    "git", "diff", "--name-only",
                    "--diff-filter=ACMRT", target
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            files = [
                f.strip()
                for f in result.stdout.splitlines()
                if f.strip()
            ]

            valid_files = []

            for filename in files:
                path = Path(filename)

                if not path.is_file():
                    continue

                if any(part in ignored_dirs for part in path.parts):
                    continue

                if path.suffix.lower() in allowed_exts:
                    valid_files.append(filename)

            return sorted(set(valid_files))

        except subprocess.CalledProcessError:
            continue

    return []


def get_file_diff_or_content(filepath: str) -> str:
    raw_lines = Path(filepath).read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines()

    return "\n".join(
        f"{idx}: {line}"
        for idx, line in enumerate(raw_lines, start=1)
    )


def get_candidate_models(client: genai.Client) -> list[str]:
    preferred = [
        "gemini-3.5-flash-lite",
        "gemini-3.8-flash",
        "gemini-3.1-pro-preview",
        "gemini-3.8-flash-lite",
    ]

    try:
        available = []

        for model in client.models.list():
            methods = (
                getattr(model, "supported_actions", None)
                or getattr(model, "supported_generation_methods", None)
                or []
            )

            name = (
                getattr(model, "name", "") or ""
            ).replace("models/", "")

            if (
                "generateContent" in methods
                and "gemini" in name
                and "2.5" not in name
                and "2.0" not in name
                and "embedding" not in name
                and "image" not in name
            ):
                available.append(name)

        ordered = [
            model for model in preferred
            if model in available
        ]

        for model in available:
            if model not in ordered and (
                "flash" in model or "pro" in model
            ):
                ordered.append(model)

        if ordered:
            return ordered[:5]

    except Exception as error:
        print(f"Model discovery warning: {error}")

    return preferred


def analyze_file(
    client: genai.Client,
    filepath: str,
    code_content: str,
    candidate_models: list[str]
) -> list[CodeIssue]:

    prompt = (
        f"You are an expert application security auditor. "
        f"Analyze `{filepath}` for security vulnerabilities including "
        "buffer overflows, gets(), format string bugs, command injection, "
        "SQL injection, integer overflows, use-after-free, double free, "
        "path traversal and hardcoded secrets.\n\n"

        "Inspect the entire supplied file carefully.\n"
        "Report only genuine, actionable security issues.\n"
        "Use the exact integer line number shown at the start of each line.\n"
        "Severity must be Critical, High, Medium or Low.\n"
        "Never invent line numbers.\n"
        "Provide a clear explanation and a practical correction.\n\n"

        f"CODE:\n{code_content}"
    )

    errors = []

    for attempt in range(5):
        current_model = candidate_models[
            attempt % len(candidate_models)
        ]

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

            if (
                response.parsed
                and getattr(response.parsed, "issues", None) is not None
            ):
                return response.parsed.issues

            raw_text = (response.text or "").strip()

            if raw_text:
                data = json.loads(raw_text)
                return [
                    CodeIssue(**item)
                    for item in data.get("issues", [])
                ]

            errors.append(f"{current_model}: empty response")

        except APIError as error:
            message = (
                f"{current_model} ({error.code}): {error.message}"
            )
            errors.append(message)

            print(
                f"[Attempt {attempt + 1}/5] {message}"
            )

            if attempt < 4:
                time.sleep(3 * (attempt + 1))

        except Exception as error:
            message = (
                f"{current_model} ({type(error).__name__}): {error}"
            )
            errors.append(message)

            print(
                f"[Attempt {attempt + 1}/5] {message}"
            )

            if attempt < 4:
                time.sleep(2)

    return [
        CodeIssue(
            severity="ERROR",
            line="1",
            issue="Gemini review failed: " + " | ".join(errors),
            fix="Check the Gemini API key, model availability, quota and billing. Retry the review.",
        )
    ]


def parse_line_num(raw_line: str) -> int:
    digits = "".join(
        ch for ch in str(raw_line).split("-")[0]
        if ch.isdigit()
    )

    return max(1, int(digits)) if digits else 1


def escape_command(value: str) -> str:
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


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


def create_report(
    results: list[dict],
    repo: str,
    sha: str
) -> tuple[str, str]:

    issues = [
        item for result in results
        for item in result["issues"]
    ]

    error_count = sum(
        item["severity"].upper() == "ERROR"
        for item in issues
    )

    if error_count:
        status = "ERROR"
    elif issues:
        status = "FAILED"
    else:
        status = "PASSED"

    counts = {
        severity: sum(
            item["severity"].upper() == severity
            for item in issues
        )
        for severity in (
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR"
        )
    }

    report = {
        "status": status,
        "repository": repo,
        "commit": sha,
        "total_issues": len(issues),
        "severity_counts": counts,
        "results": results,
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
        f"**Total findings:** {len(issues)}",
        "",
        "## Security Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for severity, count in counts.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend(["", "## Detected Issues", ""])

    if not issues:
        lines.append(
            "No security vulnerabilities detected in the reviewed files."
        )

    for result in results:
        filepath = result["file"]

        for item in result["issues"]:
            severity = item["severity"].upper()
            line_num = parse_line_num(item["line"])

            link = get_source_link(
                repo, sha, filepath, line_num
            )

            lines.extend([
                f"### {severity}: {item['issue']}",
                "",
                f"**File:** `{filepath}`",
                "",
                f"**Line:** {line_num}",
                "",
                f"**Suggested fix:** {item['fix']}",
                "",
                f"[REFIX ERRORS - Open affected code]({link})",
                "",
                "---",
                "",
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


def update_pr_comment(markdown: str) -> None:
    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    pr_number = os.getenv("PR_NUMBER", "")

    if not token or not repo or not pr_number:
        print("PR comment skipped: GitHub credentials unavailable.")
        return

    api_base = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }

    try:
        request = urllib.request.Request(
            f"{api_base}?per_page=100",
            headers=headers,
        )

        with urllib.request.urlopen(request, timeout=20) as response:
            comments = json.loads(response.read().decode("utf-8"))

        existing_comment = next(
            (
                comment for comment in comments
                if COMMENT_MARKER in comment.get("body", "")
            ),
            None,
        )

        if existing_comment:
            url = (
                f"{api_base}/{existing_comment['id']}"
            )
            method = "PATCH"
            print("Updating existing PR security report.")
        else:
            url = api_base
            method = "POST"
            print("Creating new PR security report.")

        payload = json.dumps({
            "body": markdown
        }).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=payload,
            headers=headers,
            method=method,
        )

        with urllib.request.urlopen(request, timeout=20) as response:
            print(
                f"PR security report published: HTTP {response.status}"
            )

    except Exception as error:
        print(f"PR comment warning: {error}")
        print("The security review will continue.")


def main() -> None:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    if not api_key:
        print("::error::GEMINI_API_KEY secret is missing.")
        sys.exit(1)

    repo = os.getenv("GITHUB_REPOSITORY", "")
    sha = (
        os.getenv("GITHUB_HEAD_SHA", "")
        or os.getenv("GITHUB_SHA", "")
    )

    files = get_changed_files()

    print(f"Changed files: {files}")

    results = []

    if files:
        client = genai.Client(api_key=api_key)
        candidate_models = get_candidate_models(client)

        print(f"Active models: {candidate_models}")

        for filepath in files:
            print(f"\nReviewing: {filepath}")

            content = get_file_diff_or_content(filepath)

            if not content.strip():
                continue

            issues = analyze_file(
                client,
                filepath,
                content,
                candidate_models
            )

            results.append({
                "file": filepath,
                "issues": [
                    {
                        "severity": issue.severity,
                        "line": issue.line,
                        "issue": issue.issue,
                        "fix": issue.fix,
                    }
                    for issue in issues
                ],
            })

    status, markdown = create_report(
        results,
        repo,
        sha
    )

    # Publish the PR report before failing the job.
    update_pr_comment(markdown)

    total_issues = sum(
        len(result["issues"])
        for result in results
    )

    # Generate native GitHub inline annotations.
    for result in results:
        filepath = result["file"]

        for issue in result["issues"]:
            line_num = parse_line_num(issue["line"])

            message = (
                f"[{issue['severity']}] "
                f"{issue['issue']} | Fix: {issue['fix']}"
            )

            message = escape_command(message)
            safe_file = escape_command(filepath).replace(
                ",", "%2C"
            ).replace(":", "%3A")

            print(
                f"::error file={safe_file},line={line_num}::{message}"
            )

    print(f"\nSecurity review status: {status}")
    print(f"Total findings: {total_issues}")

    if status == "ERROR":
        sys.exit(1)

    if status == "FAILED":
        sys.exit(1)

    print("PASSED: No security vulnerabilities detected.")


if __name__ == "__main__":
    main()