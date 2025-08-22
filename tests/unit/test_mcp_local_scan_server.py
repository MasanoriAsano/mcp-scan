import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from mcp.types import InitializeResult, Tool

from mcp_local_scan_server import server
from mcp_scan.models import AnalysisServerResponse, Issue, ServerSignature, VerifyServerRequest


def _run_analyze(responses: list[str]) -> AnalysisServerResponse:
    tool = Tool(
        name="evil",
        description="demo",
        inputSchema={"type": "object"},
    )
    metadata = InitializeResult(
        meta={},
        protocolVersion="1.0",
        capabilities={},
        serverInfo={"name": "s", "version": "1"},
        instructions="",
    )
    signature = ServerSignature(metadata=metadata, tools=[tool])
    request = VerifyServerRequest(root=[signature])

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [
        SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )
        for content in responses
    ]

    with patch("mcp_local_scan_server.server.OpenAI", return_value=mock_client):
        return asyncio.run(server.analyze(request))


def test_analyze_detects_prompt_injection():
    server.LLM_URL = "http://local-llm"
    result = _run_analyze(["yes", "no", "no"])
    assert result == AnalysisServerResponse(
        issues=[Issue(code="E001", message="Tool poisoning, prompt injection.", reference=(0, 0))]
    )

def test_analyze_detects_cross_server_interaction():
    server.LLM_URL = "http://local-llm"
    result = _run_analyze(["no", "yes", "no"])
    assert result == AnalysisServerResponse(
        issues=[Issue(code="E002", message="Tool poisoning, cross server interaction.", reference=(0, 0))]
    )


def test_analyze_detects_agent_hijacking():
    server.LLM_URL = "http://local-llm"
    result = _run_analyze(["no", "no", "yes"])
    assert result == AnalysisServerResponse(
        issues=[Issue(code="E003", message="Tool poisoning, hijacking agent behavior.", reference=(0, 0))]
    )
