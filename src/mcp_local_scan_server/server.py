"""Minimal local analysis server for MCP Scan."""

import uvicorn
from fastapi import FastAPI

from mcp_scan.models import AnalysisServerResponse, VerifyServerRequest

app = FastAPI()


@app.post("/api/v1/public/mcp-analysis", response_model=AnalysisServerResponse)
async def analyze(request: VerifyServerRequest) -> AnalysisServerResponse:
    """Mock analysis endpoint returning an empty issue list."""
    return AnalysisServerResponse(issues=[])


def run(host: str = "0.0.0.0", port: int = 8128) -> None:
    """Run the local analysis server using uvicorn."""
    uvicorn.run(app, host=host, port=port)


def main() -> None:
    """Entry point for running via ``uv run mcp-local-scan-server``."""
    import argparse

    parser = argparse.ArgumentParser(description="Local mock analysis server")
    parser.add_argument("--port", type=int, default=8128, help="Port to bind to")
    args = parser.parse_args()

    run(port=args.port)


if __name__ == "__main__":  # pragma: no cover - manual run
    main()
