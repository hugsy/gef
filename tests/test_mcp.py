"""
Tests for GEF MCP Server
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys

# Mock gdb module before importing MCP modules
sys.modules['gdb'] = MagicMock()

from mcp.models import (
    RegisterState,
    MemoryContent,
    MemoryRegion,
    HeapChunk,
    HeapInfo,
    StackFrame,
    Breakpoint,
    ExecutionState,
    CommandResult,
)
from mcp.tools import (
    execute_command,
    get_registers,
    inspect_memory,
    get_memory_map,
    heap_analysis,
    stack_analysis,
    breakpoint_set,
    continue_execution,
)


class TestModels:
    """Test data models"""

    def test_register_state(self):
        """Test RegisterState model"""
        regs = {"rax": 0x1234, "rbx": 0x5678}
        state = RegisterState(registers=regs, pc=0x1000, sp=0x2000)
        result = state.to_dict()

        assert result["registers"]["rax"] == "0x1234"
        assert result["registers"]["rbx"] == "0x5678"
        assert result["pc"] == "0x1000"
        assert result["sp"] == "0x2000"

    def test_memory_content(self):
        """Test MemoryContent model"""
        data = b"Hello\x00World"
        content = MemoryContent(address=0x400000, data=data, ascii_repr="Hello.World")
        result = content.to_dict()

        assert result["address"] == "0x400000"
        assert result["hex"] == data.hex()
        assert result["ascii"] == "Hello.World"
        assert result["size"] == len(data)

    def test_memory_region(self):
        """Test MemoryRegion model"""
        region = MemoryRegion(
            start=0x400000,
            end=0x401000,
            size=0x1000,
            permissions="r-xp",
            name="/bin/test",
            offset=0
        )
        result = region.to_dict()

        assert result["start"] == "0x400000"
        assert result["end"] == "0x401000"
        assert result["size"] == 0x1000
        assert result["permissions"] == "r-xp"
        assert result["name"] == "/bin/test"

    def test_heap_chunk(self):
        """Test HeapChunk model"""
        chunk = HeapChunk(
            address=0x602000,
            size=0x20,
            prev_size=0,
            flags="PREV_INUSE",
            fd=0x602020,
            bk=0x602040
        )
        result = chunk.to_dict()

        assert result["address"] == "0x602000"
        assert result["size"] == 0x20
        assert result["flags"] == "PREV_INUSE"

    def test_stack_frame(self):
        """Test StackFrame model"""
        frame = StackFrame(address=0x400100, function="main", offset=0)
        result = frame.to_dict()

        assert result["address"] == "0x400100"
        assert result["function"] == "main"
        assert result["offset"] == 0

    def test_breakpoint(self):
        """Test Breakpoint model"""
        bp = Breakpoint(
            number=1,
            address=0x400000,
            enabled=True,
            type="breakpoint",
            location="main"
        )
        result = bp.to_dict()

        assert result["number"] == 1
        assert result["address"] == "0x400000"
        assert result["enabled"] is True
        assert result["type"] == "breakpoint"

    def test_execution_state(self):
        """Test ExecutionState model"""
        state = ExecutionState(
            stopped=True,
            reason="breakpoint",
            signal=None,
            address=0x400000
        )
        result = state.to_dict()

        assert result["stopped"] is True
        assert result["reason"] == "breakpoint"
        assert result["address"] == "0x400000"

    def test_command_result(self):
        """Test CommandResult model"""
        result_obj = CommandResult(
            output="test output",
            error="",
            return_code=0
        )
        result = result_obj.to_dict()

        assert result["output"] == "test output"
        assert result["error"] == ""
        assert result["return_code"] == 0


class TestTools:
    """Test MCP tools"""

    @patch('mcp.tools.gdb')
    def test_execute_command(self, mock_gdb):
        """Test execute_command tool"""
        mock_gdb.execute.return_value = "test output"

        result = execute_command("help")

        assert result["output"] == "test output"
        assert result["return_code"] == 0
        mock_gdb.execute.assert_called_once_with("help", to_string=True)

    @patch('mcp.tools.gdb')
    def test_get_registers(self, mock_gdb):
        """Test get_registers tool"""
        mock_gdb.parse_and_eval.side_effect = lambda x: {
            "$rax": 0x1234,
            "$rbx": 0x5678,
            "$rip": 0x1000,
            "$rsp": 0x2000,
            "$eflags": 0x0,
        }.get(x, 0)

        result = get_registers()

        assert "registers" in result
        assert "pc" in result
        assert "sp" in result

    @patch('mcp.tools.gdb')
    def test_inspect_memory(self, mock_gdb):
        """Test inspect_memory tool"""
        mock_inferior = Mock()
        mock_inferior.read_memory.return_value = b"Hello\x00World"
        mock_gdb.selected_inferior.return_value = mock_inferior

        result = inspect_memory(0x400000, 11)

        assert result["address"] == "0x400000"
        assert result["size"] == 11
        assert "hex" in result
        assert "ascii" in result

    @patch('mcp.tools.gdb')
    def test_get_memory_map(self, mock_gdb):
        """Test get_memory_map tool"""
        mock_inferior = Mock()
        mock_inferior.pid = 12345
        mock_gdb.selected_inferior.return_value = mock_inferior

        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value = [
                "00400000-00401000 r-xp 00000000 08:01 1234 /bin/test\n"
            ]
            result = get_memory_map()

        assert "regions" in result

    @patch('mcp.tools.gdb')
    def test_heap_analysis(self, mock_gdb):
        """Test heap_analysis tool"""
        mock_gdb.execute.return_value = ""

        result = heap_analysis()

        assert "chunks" in result
        assert "top" in result

    @patch('mcp.tools.gdb')
    def test_stack_analysis(self, mock_gdb):
        """Test stack_analysis tool"""
        mock_gdb.execute.return_value = "#0 0x0000000000400100 in main ()\n#1 0x0000000000400200 in _start ()"

        result = stack_analysis()

        assert "frames" in result

    @patch('mcp.tools.gdb')
    def test_breakpoint_set(self, mock_gdb):
        """Test breakpoint_set tool"""
        mock_gdb.execute.return_value = "Breakpoint 1 at 0x400000"

        result = breakpoint_set("main", "breakpoint")

        assert result["number"] == 1
        assert result["address"] == "0x400000"
        assert result["type"] == "breakpoint"

    @patch('mcp.tools.gdb')
    def test_continue_execution(self, mock_gdb):
        """Test continue_execution tool"""
        mock_gdb.execute.return_value = "Program received signal SIGSEGV"
        mock_gdb.parse_and_eval.return_value = 0x400000

        result = continue_execution()

        assert result["stopped"] is True
        assert result["reason"] == "signal"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
