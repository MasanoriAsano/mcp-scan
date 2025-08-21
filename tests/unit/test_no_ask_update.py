import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_scan.cli import run_scan_inspect
from mcp_scan.models import Issue, ScanPathResult


@patch("mcp_scan.cli.input", return_value="Y")
@patch("mcp_scan.cli.print_scan_result")
@patch("mcp_scan.cli.MCPScanner")
def test_update_prompt_yes(mock_scanner_cls, mock_print, mock_input):
    scanner_instance = AsyncMock()
    issue = Issue(code="W001", message="warn")
    scanner_instance.scan.return_value = [ScanPathResult(path="p", servers=[], issues=[issue])]
    scanner_instance.storage_file = MagicMock()
    mock_scanner_cls.return_value.__aenter__.return_value = scanner_instance

    args = SimpleNamespace(
        no_ask_update=False,
        json=False,
        print_errors=False,
        full_toxic_flows=False,
        control_server=None,
        push_key=None,
        email=None,
        opt_out=False,
        local_only=False,
    )

    asyncio.run(run_scan_inspect(mode="scan", args=args))

    mock_input.assert_called_once()
    scanner_instance.storage_file.save.assert_called_once()
    scanner_instance.scan.assert_called_with(save_results=False)


@patch("mcp_scan.cli.input", return_value="N")
@patch("mcp_scan.cli.print_scan_result")
@patch("mcp_scan.cli.MCPScanner")
def test_update_prompt_no(mock_scanner_cls, mock_print, mock_input):
    scanner_instance = AsyncMock()
    issue = Issue(code="E001", message="err")
    scanner_instance.scan.return_value = [ScanPathResult(path="p", servers=[], issues=[issue])]
    scanner_instance.storage_file = MagicMock()
    mock_scanner_cls.return_value.__aenter__.return_value = scanner_instance

    args = SimpleNamespace(
        no_ask_update=False,
        json=False,
        print_errors=False,
        full_toxic_flows=False,
        control_server=None,
        push_key=None,
        email=None,
        opt_out=False,
        local_only=False,
    )

    asyncio.run(run_scan_inspect(mode="scan", args=args))

    mock_input.assert_called_once()
    scanner_instance.storage_file.save.assert_not_called()
    scanner_instance.scan.assert_called_with(save_results=False)


@patch("mcp_scan.cli.input")
@patch("mcp_scan.cli.print_scan_result")
@patch("mcp_scan.cli.MCPScanner")
def test_no_ask_update_flag(mock_scanner_cls, mock_print, mock_input):
    scanner_instance = AsyncMock()
    issue = Issue(code="W001", message="warn")
    scanner_instance.scan.return_value = [ScanPathResult(path="p", servers=[], issues=[issue])]
    scanner_instance.storage_file = MagicMock()
    mock_scanner_cls.return_value.__aenter__.return_value = scanner_instance

    args = SimpleNamespace(
        no_ask_update=True,
        json=False,
        print_errors=False,
        full_toxic_flows=False,
        control_server=None,
        push_key=None,
        email=None,
        opt_out=False,
        local_only=False,
    )

    asyncio.run(run_scan_inspect(mode="scan", args=args))

    mock_input.assert_not_called()
    scanner_instance.storage_file.save.assert_not_called()
    scanner_instance.scan.assert_called_with(save_results=True)
