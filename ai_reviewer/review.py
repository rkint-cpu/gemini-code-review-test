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
from pydantic import BaseModel, Field


# ==================================================
# CONFIGURATION
# ==================================================

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
MAX_ATTEMPTS_PER_MODEL = 2
MAX_MODELS_TO_TRY = 5


# ==================================================
# RESPONSE SCHEMAS
# ==================================================

class CodeIssue(BaseModel):
    severity: str = Field(
        description="Critical, High, Medium, or Low"
    )
    line: str = Field(
        description="Exact source line number"
    )
    issue: str = Field(
        description="Description of the vulnerability"
    )
    fix: str = Field(
        description="Practical recommended correction"
    )


class ReviewResponse(BaseModel):
    issues: list[CodeIssue]


# ==================================================
# CHANGED FILE DISCOVERY
# ==================================================

def get_changed_files() -> list[str]:

    head_sha = os.getenv("GITHUB_HEAD_SHA", "").strip()

    if not head_sha:
        raise RuntimeError("GITHUB_HEAD_SHA is missing.")

    # Find the parent of the latest PR commit.
    before_result = subprocess.run(
        ["git", "rev-parse", f"{head_sha}^"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True
    )

    before_sha = before_result.stdout.strip()

    print(
        f"Finding files changed in latest commit: "
        f"{before_sha[:8]}...{head_sha[:8]}",
        flush=True
    )

    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMRT",
            before_sha,
            head_sha
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
            print(
                f"Skipping reviewer file: {filename}",
                flush=True
            )
            continue

        if not path.is_file():
            continue

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        if any(
            part in IGNORED_DIRECTORIES
            for part in path.parts
        ):
            continue

        if path.stat().st_size > MAX_FILE_SIZE:
            print(
                f"Skipping oversized file: {filename}",
                flush=True
            )
            continue

        files.append(filename)

    return sorted(set(files))


# ==================================================
# READ SOURCE CODE
# ==================================================

def get_file_content(filepath: str) -> str:

    lines = Path(filepath).read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    return "\n".join(
        f"{number}: {line}"
        for number, line in enumerate(lines, start=1)
    )


# ==================================================
# DISCOVER AVAILABLE GEMINI MODELS
# ==================================================

def get_candidate_models(client: genai.Client) -> list[str]:

    print(
        "Discovering available Gemini models...",
        flush=True
    )

    available = []

    try:

        for model in client.models.list():

            name = (
                getattr(model, "name", "") or ""
            ).replace("models/", "")

            actions = (
                getattr(model, "supported_actions", None)
                or getattr(
                    model,
                    "supported_generation_methods",
                    None
                )
                or []
            )

            if isinstance(actions, str):
                actions = [actions]

            supports_generation = any(
                str(action).lower() == "generatecontent"
                for action in actions
            )

            if (
                name
                and "gemini" in name.lower()
                and supports_generation
                and "embedding" not in name.lower()
                and "image" not in name.lower()
                and name not in available
            ):
                available.append(name)

    except Exception as error:

        raise RuntimeError(
            "Could not retrieve available Gemini models. "
            f"{type(error).__name__}: {error}"
        ) from error

    if not available:

        raise RuntimeError(
            "Google returned no models supporting generateContent "
            "for this API key. Check API access and model availability."
        )

    flash_models = [
        name for name in available
        if "flash" in name.lower()
    ]

    other_models = [
        name for name in available
        if name not in flash_models
    ]

    ordered = (
        flash_models + other_models
    )[:MAX_MODELS_TO_TRY]

    print(
        f"Models available for review: {ordered}",
        flush=True
    )

    return ordered


# ==================================================
# BUILD SECURITY REVIEW PROMPT
# ==================================================

def build_prompt(filepath: str, content: str) -> str:

    return f"""
You are an expert application security auditor.

Review the supplied source file for genuine, actionable
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
12. Null pointer dereferences
13. Memory leaks
14. Other serious security weaknesses

IMPORTANT RULES:

- Review the actual supplied code.
- Use the exact line number shown at the start of each line.
- Never invent line numbers.
- Report only genuine, actionable security issues.
- Do not report safe operations as vulnerabilities.
- Do not report vulnerabilities that have already been fixed.
- Explain why each reported issue is dangerous.
- Give a practical correction for each finding.
- Do not report a placeholder test secret as a real credential
  unless it creates a concrete security risk.
- Do not flag subprocess calls using an argument list and
  shell=False merely because subprocess is used.
- If no genuine vulnerabilities exist, return an empty issues list.

Severity must be one of:

Critical
High
Medium
Low

SOURCE CODE:

{content}
"""


# ==================================================
# PARSE GEMINI RESPONSE
# ==================================================

def parse_response(response) -> list[CodeIssue]:

    if response.parsed is not None:

        parsed = response.parsed

        if isinstance(parsed, ReviewResponse):
            return parsed.issues

        if isinstance(parsed, dict):
            return [
                CodeIssue(**item)
                for item in parsed.get("issues", [])
            ]

    raw_text = (response.text or "").strip()

    if not raw_text:
        raise RuntimeError(
            "Gemini returned an empty response."
        )

    if raw_text.startswith("```"):

        raw_text = raw_text.replace("```json", "", 1)
        raw_text = raw_text.replace("```", "").strip()

    data = json.loads(raw_text)

    return [
        CodeIssue(**item)
        for item in data.get("issues", [])
    ]


# ==================================================
# ANALYZE ONE FILE
# ==================================================

def analyze_file(
    client: genai.Client,
    filepath: str,
    content: str,
    candidate_models: list[str]
) -> tuple[list[CodeIssue], str]:

    prompt = build_prompt(filepath, content)

    errors = []

    for model in candidate_models:

        for attempt in range(MAX_ATTEMPTS_PER_MODEL):

            print(
                f"Reviewing {filepath} using {model} "
                f"(attempt {attempt + 1}/{MAX_ATTEMPTS_PER_MODEL})",
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

                issues = parse_response(response)

                print(
                    f"Gemini completed review of {filepath}. "
                    f"Findings: {len(issues)}",
                    flush=True
                )

                return issues, ""

            except APIError as error:

                message = (
                    f"{model}: API error "
                    f"{getattr(error, 'code', 'unknown')}: "
                    f"{getattr(error, 'message', str(error))}"
                )

                errors.append(message)

                print(message, flush=True)

            except Exception as error:

                message = (
                    f"{model}: {type(error).__name__}: {error}"
                )

                errors.append(message)

                print(message, flush=True)

            if attempt < MAX_ATTEMPTS_PER_MODEL - 1:

                delay = 3 * (attempt + 1)

                print(
                    f"Retrying in {delay} seconds...",
                    flush=True
                )

                time.sleep(delay)

    return [], (
        "All available Gemini models failed. "
        + " | ".join(errors)
    )


# ==================================================
# LINE NUMBER VALIDATION
# ==================================================

def parse_line_num(raw_line: str) -> int:

    match = str(raw_line).strip().split(":", 1)[0]

    try:
        return int(match)
    except (ValueError, TypeError):
        return 0


# ==================================================
# VALIDATE SECURITY FINDINGS
# ==================================================

def validate_issues(
    issues: list[CodeIssue],
    filepath: str
) -> list[dict]:

    source_lines = Path(filepath).read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    validated = []

    allowed_severities = {
        "CRITICAL", "HIGH", "MEDIUM", "LOW"
    }

    for issue in issues:

        severity = issue.severity.strip().upper()

        if severity not in allowed_severities:
            print(
                f"Ignoring invalid severity: {issue.severity}",
                flush=True
            )
            continue

        line_num = parse_line_num(issue.line)

        if not 1 <= line_num <= len(source_lines):
            print(
                f"Ignoring invalid line: {filepath}:{line_num}",
                flush=True
            )
            continue

        validated.append({
            "severity": severity,
            "line": issue.line,
            "line_number": line_num,
            "issue": issue.issue.strip(),
            "fix": issue.fix.strip()
        })

    return validated


    # ==================================================
# SOURCE CODE LINKS
# ==================================================

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


# ==================================================
# BUILD SECURITY REPORT
# ==================================================

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
            issue["severity"] == severity
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
        "# AI Security Review Report",
        "",
        f"**Status:** {status}",
        "",
        f"**Commit reviewed:** `{sha}`",
        "",
        f"**Total findings:** {len(all_issues)}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Findings |",
        "|---|---:|"
    ]

    for severity, count in counts.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend([
        "",
        "## Detailed Findings",
        ""
    ])

    if not results:
        lines.append(
            "No supported changed source files were found."
        )

    elif not all_issues and not review_errors:
        lines.append(
            "No security vulnerabilities or critical bugs detected."
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
            line_num = issue["line_number"]
            link = get_source_link(
                repo, sha, filepath, line_num
            )

            lines.extend([
                f"#### {issue['severity']}: {issue['issue']}",
                "",
                f"**Line:** {line_num}",
                "",
                f"**Suggested fix:** {issue['fix']}",
                "",
                f"[FIX ERROR - Open affected code]({link})",
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
# UPDATE OR CREATE PR COMMENT
# ==================================================

def update_pr_comment(markdown: str) -> bool:

    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    pr_number = os.getenv("PR_NUMBER", "")

    if not token or not repo or not pr_number:
        print(
            "PR comment credentials are missing.",
            flush=True
        )
        return False

    base_url = f"https://api.github.com/repos/{repo}"

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json"
    }

    payload = json.dumps({
        "body": markdown
    }).encode("utf-8")

    def send_request(url, method):

        request = urllib.request.Request(
            url,
            data=payload,
            headers=headers,
            method=method
        )

        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:

            print(
                f"PR report published: HTTP {response.status}",
                flush=True
            )

            return True

    try:

        comments_url = (
            f"{base_url}/issues/{pr_number}/comments?per_page=100"
        )

        request = urllib.request.Request(
            comments_url,
            headers=headers
        )

        with urllib.request.urlopen(
            request,
            timeout=30
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

            comment_id = existing.get("id")

            update_url = (
                f"{base_url}/issues/comments/{comment_id}"
            )

            print(
                "Updating existing AI security report...",
                flush=True
            )

            try:
                return send_request(
                    update_url,
                    "PATCH"
                )

            except urllib.error.HTTPError as error:

                if error.code != 404:
                    raise

                print(
                    "Existing comment returned 404. "
                    "Creating a new report instead...",
                    flush=True
                )

        create_url = (
            f"{base_url}/issues/{pr_number}/comments"
        )

        print(
            "Creating AI security report...",
            flush=True
        )

        return send_request(
            create_url,
            "POST"
        )

    except urllib.error.HTTPError as error:

        details = error.read().decode(
            "utf-8",
            errors="replace"
        )

        print(
            f"::error::GitHub API returned HTTP "
            f"{error.code}: {details}",
            flush=True
        )

        return False

    except Exception as error:

        print(
            f"::error::Could not publish PR report: "
            f"{type(error).__name__}: {error}",
            flush=True
        )

        return False


# ==================================================
# GITHUB ACTIONS STEP SUMMARY
# ==================================================

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

        print(
            "GitHub Actions summary generated.",
            flush=True
        )

    except Exception as error:

        print(
            f"Summary warning: {error}",
            flush=True
        )


# ==================================================
# ESCAPE GITHUB ACTIONS COMMAND VALUES
# ==================================================

def escape_command(value: str) -> str:

    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(",", "%2C")
        .replace(":", "%3A")
    )


# ==================================================
# PUBLISH INLINE ANNOTATIONS
# ==================================================

def publish_annotations(results: list[dict]) -> None:

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
                f"::{level} "
                f"file={escape_command(filepath)},"
                f"line={issue['line_number']}::"
                f"{escape_command(message)}",
                flush=True
            )


# ==================================================
# MAIN EXECUTION
# ==================================================

def main() -> None:

    api_key = os.getenv(
        "GEMINI_API_KEY",
        ""
    ).strip()

    if not api_key:

        print(
            "::error::GEMINI_API_KEY is missing.",
            flush=True
        )

        sys.exit(1)

    repo = os.getenv(
        "GITHUB_REPOSITORY",
        ""
    )

    sha = (
        os.getenv("GITHUB_HEAD_SHA", "")
        or os.getenv("GITHUB_SHA", "")
    )

    print(
        "Starting AI security review...",
        flush=True
    )

    results = []

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

            candidate_models = get_candidate_models(
                client
            )

            for filepath in files:

                print(
                    f"\nReviewing file: {filepath}",
                    flush=True
                )

                content = get_file_content(filepath)

                if not content.strip():

                    results.append({
                        "file": filepath,
                        "issues": [],
                        "error": ""
                    })

                    continue

                issues, error = analyze_file(
                    client,
                    filepath,
                    content,
                    candidate_models
                )

                validated_issues = validate_issues(
                    issues,
                    filepath
                )

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
                        f"Review completed for {filepath}. "
                        f"Findings: {len(validated_issues)}",
                        flush=True
                    )

        status, markdown = create_report(
            results,
            repo,
            sha
        )

        comment_published = update_pr_comment(
            markdown
        )

        write_step_summary(markdown)

        publish_annotations(results)

        total_issues = sum(
            len(result["issues"])
            for result in results
        )

        print(
            "\n================================",
            flush=True
        )

        print(
            f"SECURITY REVIEW STATUS: {status}",
            flush=True
        )

        print(
            f"TOTAL FINDINGS: {total_issues}",
            flush=True
        )

        print(
            "================================",
            flush=True
        )

        if not comment_published:

            print(
                "::warning::The report could not be published "
                "as a PR comment. Check workflow permissions.",
                flush=True
            )

        if status == "ERROR":

            print(
                "::error::AI review failed. "
                "The PR must not be treated as security-approved.",
                flush=True
            )

            sys.exit(1)

        if status == "FAILED":

            print(
                "::error::Security vulnerabilities detected. "
                "Review the findings and fix the affected code.",
                flush=True
            )

            sys.exit(1)

        print(
            "PASSED: No vulnerabilities detected in reviewed files.",
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