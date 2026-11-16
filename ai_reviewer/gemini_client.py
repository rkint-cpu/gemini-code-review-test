import os
import time
from typing import List, Literal
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from google.genai.errors import APIError

MODEL_NAME = "gemini-3.8-flash"

SYSTEM_PROMPT = """
You are an expert senior software engineer and application security auditor performing automated code reviews.
Review the provided line-numbered source code strictly for:
1. Bugs & Logic Errors (e.g., division by zero, unhandled exceptions, off-by-one errors, null/None dereferences).
2. Security Vulnerabilities (e.g., hardcoded secrets/API keys, SQL injection, command injection, insecure hashing, unsafe deserialization).
3. Performance & Maintainability Issues (e.g., O(n^2) nested loops over large collections, resource leaks, redundant I/O).

Rules:
- Cite the exact line number from the provided prefixes.
- Be concise, objective, and actionable.
- If the file is clean and has no meaningful issues, return an empty issues list.
- Do NOT nitpick trivial formatting or style preferences unless they cause real bugs or maintainability hazards.
"""

class CodeIssue(BaseModel):
    line_number: int = Field(description="Exact 1-based line number where the issue occurs.")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        description="CRITICAL/HIGH for security flaws or crashes; MEDIUM/LOW for performance or maintainability."
    )
    category: Literal["Security", "Bug", "Performance", "Maintainability"] = Field(
        description="Primary classification of the finding."
    )
    description: str = Field(description="Clear, concise explanation of why this is an issue.")
    suggestion: str = Field(description="Concrete recommendation on how to fix it.")

class FileReviewResult(BaseModel):
    file_path: str = Field(description="Relative path of the reviewed file.")
    issues: List[CodeIssue] = Field(
        default_factory=list,
        description="List of detected issues. Empty if the code is clean."
    )

def get_gemini_client() -> genai.Client:
    if not os.getenv("GEMINI_API_KEY"):
        raise EnvironmentError("GEMINI_API_KEY environment variable is not set.")
    return genai.Client()

def review_file(
    client: genai.Client,
    file_path: str,
    numbered_code: str,
    max_retries: int = 3
) -> FileReviewResult:
    """Sends a single line-numbered file to Gemini with retry backoff for transient 503/429 spikes."""
    prompt = f"File path: `{file_path}`\n\nCode:\n```\n{numbered_code}\n```"

    for attempt in range(1, max_retries + 1):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=FileReviewResult,
                    temperature=0.1,
                ),
            )
            result = FileReviewResult.model_validate_json(response.text)
            result.file_path = file_path
            return result
        except APIError as exc:
            if exc.code in (429, 503) and attempt < max_retries:
                wait_seconds = 2 ** attempt
                print(f"    ⏳ Model busy (HTTP {exc.code}). Retrying {file_path} in {wait_seconds}s (attempt {attempt}/{max_retries})...")
                time.sleep(wait_seconds)
                continue
            raise