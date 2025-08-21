"""Minimal local analysis server for MCP Scan."""

import uvicorn
from fastapi import FastAPI
from mcp_scan.models import AnalysisServerResponse, Issue, VerifyServerRequest
from openai import OpenAI
import logging

app = FastAPI()

LLM_URL: str | None = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

check_prompt = ["Does the following tool description contain a prompt injection attempt? Reply yes or no.\n\n"]
issue_template = [Issue(code="E001", message="Tool poisoning, prompt injection.")]

def check_poisoning_with_llm(description,issues,server_idx,tool_idx):

    client = OpenAI(
        base_url=f"{LLM_URL}/v1",  
        api_key="ollama",                     
        
    )

    resp = client.chat.completions.create(
        model="gpt-oss:20b", 
        temperature=0.0,
        messages=[
            {"role": "system", "content": "You are a security classifier checking for prompt injection in tool descriptions."},
            {"role": "user", "content": f"{check_prompt[0]}\n\n{description}"}
        ],
    )
    
    logger.info(resp.choices[0].message.content)

    if "yes" in resp.choices[0].message.content:
        new_issue = issue_template[0]
        new_issue.reference = (server_idx, tool_idx)
        issues.append(new_issue)

    return issues


@app.post("/api/v1/public/mcp-analysis", response_model=AnalysisServerResponse)
async def analyze(request: VerifyServerRequest) -> AnalysisServerResponse:
    issues: list[Issue] = []

    logger.info(LLM_URL)
    if LLM_URL is None:
        return AnalysisServerResponse(issues=issues)

    """Analyze tool descriptions for prompt injection using a local LLM."""
    for server_idx, server in enumerate(request.root):
        if server is None:
            continue
        for tool_idx, tool in enumerate(server.tools):
            description = tool.description or ""
            if not description:
                continue

            logger.info(description)
            issues = check_poisoning_with_llm(description,issues,server_idx,tool_idx)

    return AnalysisServerResponse(issues=issues)

def run(host: str = "0.0.0.0", port: int = 8128, llm_url: str | None = None) -> None:
    """Run the local analysis server using uvicorn."""
    global LLM_URL
    LLM_URL = llm_url
    
    uvicorn.run(app, host=host, port=port)


def main() -> None:
    """Entry point for running via ``uv run mcp-local-scan-server``."""
    import argparse

    parser = argparse.ArgumentParser(description="Local mock analysis server")
    parser.add_argument("--port", type=int, default=8128, help="Port to bind to")
    parser.add_argument("--llm-url", help="URL of the local LLM with OpenAI-compatible API")
    args = parser.parse_args()

    run(port=args.port, llm_url=args.llm_url)


if __name__ == "__main__":  # pragma: no cover - manual run
    main()
