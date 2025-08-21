import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from mcp_scan.cli import run_scan_inspect


@patch("mcp_scan.cli.print_scan_result")
@patch("mcp_scan.cli.MCPScanner")
def test_warns_when_local_only(mock_scanner_cls, mock_print, capsys):
    scanner_instance = AsyncMock()
    scanner_instance.scan.return_value = []
    mock_scanner_cls.return_value.__aenter__.return_value = scanner_instance

    args = SimpleNamespace(
        local_only=True,
        json=False,
        print_errors=False,
        full_toxic_flows=False,
        control_server=None,
        push_key=None,
        email=None,
        opt_out=False,
    )

    asyncio.run(run_scan_inspect(mode="scan", args=args))

    captured = capsys.readouterr()
    assert "analysis server" in captured.out.lower()
