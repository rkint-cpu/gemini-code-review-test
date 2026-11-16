import sys
from dotenv import load_dotenv
from ai_reviewer.file_scanner import scan_repository
from ai_reviewer.gemini_client import get_gemini_client, review_file, FileReviewResult
from ai_reviewer.github_reporter import generate_markdown_report, publish_github_summary

def main() -> int:
    load_dotenv()

    print("🔍 Scanning repository for code files...")
    files = scan_repository(".")

    if not files:
        print("ℹ️ No supported code files found to review.")
        return 0

    print(f"📂 Found {len(files)} file(s). Starting Gemini AI review...")
    client = get_gemini_client()
    results: list[FileReviewResult] = []

    for file_path, numbered_code in files.items():
        print(f"  -> Reviewing {file_path}...")
        try:
            result = review_file(client, file_path, numbered_code)
            results.append(result)
        except Exception as exc:
            print(f"⚠️ Failed to review {file_path}: {exc}", file=sys.stderr)

    report = generate_markdown_report(results)
    print("\n" + report)
    publish_github_summary(report)

    # Always return 0 so reporting never blocks CI/CD pipelines
    return 0

if __name__ == "__main__":
    sys.exit(main())