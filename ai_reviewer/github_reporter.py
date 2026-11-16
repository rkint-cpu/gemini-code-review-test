import os
from typing import List
from ai_reviewer.gemini_client import FileReviewResult

SEVERITY_BADGES = {
    "CRITICAL": "**CRITICAL**",
    "HIGH": "**HIGH**",
    "MEDIUM": "**MEDIUM**",
    "LOW": "**LOW**",
}

def generate_markdown_report(results: List[FileReviewResult]) -> str:
    """Builds a structured Markdown report from file review results."""
    total_files = len(results)
    total_issues = sum(len(r.issues) for r in results)
    critical_or_high = sum(
        1 for r in results for issue in r.issues
        if issue.severity in ("CRITICAL", "HIGH")
    )

    lines = ["# Gemini AI Code Review Report", ""]

    if total_issues == 0:
        lines.append(f"**Status: GREEN** — Scanned **{total_files}** file(s). No issues detected.")
        return "\n".join(lines)

    status_label = "**Status: ACTION REQUIRED**" if critical_or_high > 0 else "**Status: WARNINGS FOUND**"
    lines.extend([
        f"{status_label} — Scanned **{total_files}** file(s) and found **{total_issues}** issue(s) ({critical_or_high} Critical/High).",
        "",
        "---",
        ""
    ])

    for result in results:
        if not result.issues:
            lines.append(f"### `{result.file_path}`")
            lines.append("No issues found.\n")
            continue

        lines.append(f"### `{result.file_path}` ({len(result.issues)} issue(s))")
        lines.append("")
        lines.append("| Line | Severity | Category | Issue | Recommended Fix |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")

        for issue in sorted(result.issues, key=lambda x: x.line_number):
            badge = SEVERITY_BADGES.get(issue.severity, issue.severity)
            desc = issue.description.replace("|", "\\|").replace("\n", " ")
            fix = issue.suggestion.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{issue.line_number}` | {badge} | {issue.category} | {desc} | {fix} |")

        lines.append("")

    return "\n".join(lines)

def publish_github_summary(markdown_report: str) -> None:
    """Appends the report to GITHUB_STEP_SUMMARY if running inside GitHub Actions."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(markdown_report + "\n")