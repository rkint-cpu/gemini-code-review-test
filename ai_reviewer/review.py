import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel, Field


# ==================================================
# CONFIGURATION
# ==================================================

MODEL_NAME = "gemini-3.8-flash"

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

IGNORED_FILES = {
    "ai_reviewer/review.py",
    "ai_reviewer/review_backup.py"
}

MAX_FILE_SIZE = 200_000
MAX_ATTEMPTS = 3


# ==================================================
# AI RESPONSE SCHEMAS
# ==================================================

class CodeIssue(BaseModel):
    severity: str
    line: int = Field(ge=1)
    issue: str
    fix: str


class ReviewResponse(BaseModel):
    issues: list[CodeIssue]


# ==================================================
# GET CHANGED FILES
# ==================================================

def get_changed_files():

    base_ref = os.getenv("GITHUB_BASE_REF", "")

    if not base_ref:
        raise RuntimeError("GITHUB_BASE_REF is missing.")

    comparison = f"origin/{base_ref}...HEAD"

    print(f"Comparing changes: {comparison}", flush=True)

    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMRT",
            comparison
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

        if filename in IGNORED_FILES:
            print(f"Skipping reviewer file: {filename}", flush=True)
            continue

        path = Path(filename)

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


# ==================================================
# READ SOURCE FILE
# ==================================================

def get_file_content(filepath):

    lines = Path(filepath).read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    numbered_lines = [
        f"{number}: {line}"
        for number, line in enumerate(lines, start=1)
    ]

    return "\n".join(numbered_lines)


# ==================================================
# GEMINI SECURITY REVIEW
# ==================================================

def analyze_file(client, filepath, content):

    prompt = f"""
You are a senior application security engineer performing
a careful source-code security audit.

Review the following complete source file.

FILE: {filepath}

Look for genuine, exploitable security problems, including:

1. Buffer overflows
2. Unsafe strcpy, gets and memory operations
3. Format string vulnerabilities
4. OS command injection
5. SQL injection
6. Integer overflow
7. Use-after-free
8. Double-free
9. Path traversal
10. Hardcoded credentials and real secrets
11. Insecure file handling
12. Authentication and authorization weaknesses
13. Other serious security vulnerabilities

IMPORTANT RULES:

- The source code has line numbers at the beginning of each line.
- Return the exact source line number for every finding.
- Never invent line numbers.
- Only report real, actionable vulnerabilities.
- Do not report safe code as vulnerable.
- Do not report vulnerabilities that have already been fixed.
- Do not report a dummy test placeholder as a real credential.
- Explain the security impact clearly.
- Give a practical correction for every finding.
- Severity must be exactly one of:
  Critical, High, Medium, Low.
- If no vulnerabilities exist, return an empty issues list.
- Do not return a general summary as a security finding.

Return the result using the required JSON schema.

SOURCE CODE:

{content}
"""

    errors = []

    for attempt in range(1, MAX_ATTEMPTS + 1):

        print(
            f"Gemini review attempt {attempt}/{MAX_ATTEMPTS}: "
            f"{MODEL_NAME}",
            flush=True
        )

        try:

            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ReviewResponse,
                    temperature=0.1
                )
            )

            if response.parsed is not None:

                parsed = response.parsed

                if isinstance(parsed, ReviewResponse):
                    return parsed.issues, ""

            raw_text = (response.text or "").strip()

            if not raw_text:
                raise RuntimeError("Gemini returned an empty response.")

            data = json.loads(raw_text)

            parsed = ReviewResponse(**data)

            return parsed.issues, ""

        except APIError as error:

            message = (
                f"Gemini API error "
                f"{getattr(error, 'code', 'unknown')}: {error}"
            )

            errors.append(message)

            print(message, flush=True)

            code = getattr(error, "code", None)

            # Do not retry invalid model names, invalid requests,
            # authentication failures or permission failures.
            if code in (400, 401, 403, 404):
                break

        except (json.JSONDecodeError, ValueError) as error:

            message = f"Invalid AI response: {error}"

            errors.append(message)

            print(message, flush=True)

            break

        except Exception as error:

            message = (
                f"{type(error).__name__}: {error}"
            )

            errors.append(message)

            print(message, flush=True)

        if attempt < MAX_ATTEMPTS:

            delay = attempt * 5

            print(
                f"Retrying in {delay} seconds...",
                flush=True
            )

            time.sleep(delay)

    return [], "AI REVIEW FAILED: " + " | ".join(errors)


# ==================================================
# VALIDATE FINDINGS
# ==================================================

def validate_issues(issues, filepath):

    source_lines = Path(filepath).read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    validated = []

    allowed_severities = {
        "CRITICAL", "HIGH", "MEDIUM", "LOW"
    }

    for issue in issues:

        severity = issue.severity.upper().strip()

        if severity not in allowed_severities:
            print(
                f"Ignoring invalid severity: {severity}",
                flush=True
            )
            continue

        line_number = issue.line

        if not 1 <= line_number <= len(source_lines):
            print(
                f"Ignoring invalid line: {filepath}:{line_number}",
                flush=True
            )
            continue

        validated.append({
            "severity": severity,
            "line_number": line_number,
            "issue": issue.issue,
            "fix": issue.fix
        })

    return validated


# ==================================================
# CREATE SOURCE CODE LINKS
# ==================================================

def get_source_link(repo, sha, filepath, line_number):

    encoded_path = quote(filepath, safe="/")

    return (
        f"https://github.com/{repo}/blob/"
        f"{sha}/{encoded_path}#L{line_number}"
    )


# ==================================================
# BUILD SECURITY REPORT
# ==================================================

def create_report(results, repo, sha):

    all_issues = [
        issue
        for result in results
        for issue in result["issues"]
    ]

    review_errors = [
        result
        for result in results
        if result.get("error")
    ]

    if review_errors:
        status = "ERROR"

    elif all_issues:
        status = "FAILED"

    else:
        status = "PASSED"

    severity_counts = {
        severity: sum(
            issue["severity"] == severity
            for issue in all_issues
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    report = {
        "status": status,
        "repository": repo,
        "commit": sha,
        "total_issues": len(all_issues),
        "severity_counts": severity_counts,
        "results": results
    }

    Path(REPORT_JSON).write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    lines = [
        COMMENT_MARKER,
        "# AI Security Review Report",
        "",
        f"**Status:** {status}",
        "",
        f"**Commit reviewed:** `{sha}`",
        "",
        f"**Files reviewed:** {len(results)}",
        "",
        f"**Total findings:** {len(all_issues)}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Findings |",
        "|---|---:|"
    ]

    for severity, count in severity_counts.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend([
        "",
        "## Detailed Findings",
        ""
    ])

    if not all_issues and not review_errors:
        lines.append(
            "No security vulnerabilities detected in the reviewed files."
        )

    for result in results:

        filepath = result["file"]

        lines.extend([
            f"### File: `{filepath}`",
            ""
        ])

        if result.get("error"):

            lines.extend([
                "**Review error:**",
                "",
                result["error"],
                ""
            ])

            continue

        if not result["issues"]:

            lines.extend([
                "No security vulnerabilities detected.",
                ""
            ])

            continue

        for issue in result["issues"]:

            line_number = issue["line_number"]

            link = get_source_link(
                repo,
                sha,
                filepath,
                line_number
            )

            lines.extend([
                f"#### {issue['severity']}: {issue['issue']}",
                "",
                f"**Line:** {line_number}",
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


# ==================================================
# CREATE OR UPDATE PR COMMENT
# ==================================================

def update_pr_comment(markdown):

    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    pr_number = os.getenv("PR_NUMBER", "")

    if not token or not repo or not pr_number:

        print(
            "PR comment credentials are missing.",
            flush=True
        )

        return

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json"
    }

    comments_url = (
        f"https://api.github.com/repos/{repo}"
        f"/issues/{pr_number}/comments?per_page=100"
    )

    try:

        request = urllib.request.Request(
            comments_url,
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
                comment
                for comment in comments
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

            print("Updating existing AI review comment...", flush=True)

        else:

            url = (
                f"https://api.github.com/repos/{repo}"
                f"/issues/{pr_number}/comments"
            )

            method = "POST"

            print("Creating AI review comment...", flush=True)

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
            f"PR comment publishing warning: {error}",
            flush=True
        )


# ==================================================
# GITHUB ACTIONS SUMMARY
# ==================================================

def write_step_summary(markdown):

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")

    if not summary_path:
        return

    with open(
        summary_path,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(markdown)

    print("GitHub Actions summary generated.", flush=True)


# ==================================================
# GITHUB INLINE ANNOTATIONS
# ==================================================

def escape_command(value):

    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(",", "%2C")
        .replace(":", "%3A")
    )


def publish_annotations(results):

    for result in results:

        filepath = result["file"]

        for issue in result["issues"]:

            severity = issue["severity"]

            level = (
                "warning"
                if severity in {"LOW", "MEDIUM"}
                else "error"
            )

            message = (
                f"[{severity}] {issue['issue']} "
                f"| Suggested fix: {issue['fix']}"
            )

            print(
                f"::{level} file={escape_command(filepath)},"
                f"line={issue['line_number']}::"
                f"{escape_command(message)}",
                flush=True
            )


# ==================================================
# MAIN
# ==================================================

def main():

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

    results = []

    print("Starting AI security review...", flush=True)

    try:

        files = get_changed_files()

        print(
            f"Changed source files: {files}",
            flush=True
        )

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

            for filepath in files:

                print(
                    f"\nReviewing: {filepath}",
                    flush=True
                )

                content = get_file_content(filepath)

                if not content.strip():
                    print("Skipping empty file.", flush=True)
                    continue

                issues, error = analyze_file(
                    client,
                    filepath,
                    content
                )

                validated_issues = []

                if not error:

                    validated_issues = validate_issues(
                        issues,
                        filepath
                    )

                results.append({
                    "file": filepath,
                    "issues": [
                        {
                            "severity": issue["severity"],
                            "line_number": issue["line_number"],
                            "issue": issue["issue"],
                            "fix": issue["fix"]
                        }
                        for issue in validated_issues
                    ],
                    "error": error
                })

                if error:

                    print(
                        f"Review failed for {filepath}: {error}",
                        flush=True
                    )

                else:

                    print(
                        f"Review completed: {filepath}. "
                        f"Findings: {len(validated_issues)}",
                        flush=True
                    )

        status, markdown = create_report(
            results,
            repo,
            sha
        )

        # Publish report before setting the final check result.
        update_pr_comment(markdown)

        write_step_summary(markdown)

        publish_annotations(results)

        total_findings = sum(
            len(result["issues"])
            for result in results
        )

        print("\n================================", flush=True)
        print(f"SECURITY REVIEW STATUS: {status}", flush=True)
        print(f"TOTAL FINDINGS: {total_findings}", flush=True)
        print("================================", flush=True)

        if status == "ERROR":

            print(
                "::error::AI security review failed. "
                "Check the logs and report.",
                flush=True
            )

            sys.exit(1)

        if status == "FAILED":

            print(
                "::error::Security vulnerabilities detected. "
                "Fix the reported issues before merging.",
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