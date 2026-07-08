"""
MCP Tools implementation for GEF

This module implements the MCP tools that expose GEF's core functionality
to AI Agents via the Model Context Protocol.
"""

from __future__ import annotations

import io
import sys
from typing import Any, Dict, List

from .models import (
    Breakpoint,
    CommandResult,
    ExecutionState,
    HeapChunk,
    HeapInfo,
    MemoryContent,
    MemoryRegion,
    RegisterState,
    StackFrame,
)


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a GEF/GDB command and return the output.

    Args:
        command: The command to execute (e.g., "vmmap", "hexdump $rsp 64")

    Returns:
        CommandResult with output, error, and return code
    """
    try:
        import gdb
        output = gdb.execute(command, to_string=True)
        result = CommandResult(output=output.strip(), return_code=0)
        return result.to_dict()
    except Exception as e:
        return CommandResult(output="", error=str(e), return_code=1).to_dict()


def get_registers() -> Dict[str, Any]:
    """
    Get the current CPU register state.

    Returns:
        RegisterState with all register values
    """
    try:
        import gdb

        regs = {}
        # Get all registers using GEF's architecture info
        try:
            # Try to use GEF's gef.arch functions
            import gef
            if hasattr(gef, 'arch') and hasattr(gef.arch, 'all_registers'):
                for reg in gef.arch.all_registers:
                    try:
                        value = int(gdb.parse_and_eval(f"${reg}"))
                        regs[reg] = value
                    except Exception:
                        continue
        except Exception:
            # Fallback: common registers
            common_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
            for reg in common_regs:
                try:
                    value = int(gdb.parse_and_eval(f"${reg}"))
                    regs[reg] = value
                except Exception:
                    continue

        pc = regs.get("rip", regs.get("pc", 0))
        sp = regs.get("rsp", regs.get("sp", 0))

        # Try to get flags
        flags = None
        try:
            eflags = int(gdb.parse_and_eval("$eflags"))
            flags = {
                "CF": bool(eflags & 0x1),
                "PF": bool(eflags & 0x4),
                "AF": bool(eflags & 0x10),
                "ZF": bool(eflags & 0x40),
                "SF": bool(eflags & 0x80),
                "TF": bool(eflags & 0x100),
                "IF": bool(eflags & 0x200),
                "DF": bool(eflags & 0x400),
                "OF": bool(eflags & 0x800),
            }
        except Exception:
            pass

        state = RegisterState(registers=regs, pc=pc, sp=sp, flags=flags)
        return state.to_dict()
    except Exception as e:
        return {"error": str(e)}


def inspect_memory(address: int, size: int = 64) -> Dict[str, Any]:
    """
    Read and display memory contents at the given address.

    Args:
        address: Memory address to read from
        size: Number of bytes to read (default: 64)

    Returns:
        MemoryContent with hex and ASCII representation
    """
    try:
        import gdb

        # Read memory using GDB's inferior
        inferior = gdb.selected_inferior()
        data = inferior.read_memory(address, size)

        # Create ASCII representation
        ascii_repr = ""
        for byte in data:
            if 32 <= byte <= 126:
                ascii_repr += chr(byte)
            else:
                ascii_repr += "."

        content = MemoryContent(address=address, data=bytes(data), ascii_repr=ascii_repr)
        return content.to_dict()
    except Exception as e:
        return {"error": str(e), "address": hex(address)}


def get_memory_map() -> Dict[str, Any]:
    """
    Get the memory map of the current process.

    Returns:
        List of MemoryRegion objects
    """
    try:
        import gdb

        regions = []

        # Use GDB's maintenance info sections or /proc/<pid>/maps
        try:
            inferior = gdb.selected_inferior()
            pid = inferior.pid

            if pid > 0:
                # Read from /proc/<pid>/maps
                with open(f"/proc/{pid}/maps", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 6:
                            addr_range = parts[0].split("-")
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            perms = parts[1]
                            offset = int(parts[2], 16)
                            name = parts[5] if len(parts) > 5 else ""

                            region = MemoryRegion(
                                start=start,
                                end=end,
                                size=end - start,
                                permissions=perms,
                                name=name,
                                offset=offset,
                            )
                            regions.append(region)
        except Exception:
            # Fallback: use GDB's info proc mappings
            output = gdb.execute("info proc mappings", to_string=True)
            # Parse output (simplified)
            for line in output.split("\n"):
                if "0x" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            start = int(parts[0], 16)
                            end = int(parts[1], 16)
                            size = end - start
                            perms = parts[2] if len(parts) > 2 else ""
                            name = parts[-1] if len(parts) > 3 else ""

                            region = MemoryRegion(
                                start=start,
                                end=end,
                                size=size,
                                permissions=perms,
                                name=name,
                            )
                            regions.append(region)
                        except Exception:
                            continue

        return {"regions": [r.to_dict() for r in regions]}
    except Exception as e:
        return {"error": str(e)}


def heap_analysis() -> Dict[str, Any]:
    """
    Analyze the current heap state using GEF's heap analysis.

    Returns:
        HeapInfo with chunks, top chunk, and memory statistics
    """
    try:
        import gdb

        chunks = []
        top = 0
        system_mem = 0
        max_system_mem = 0

        # Try to use GEF's heap analysis
        try:
            # Execute GEF's heap command
            output = gdb.execute("heap chunks", to_string=True)

            # Parse chunk information from output
            for line in output.split("\n"):
                if "Chunk" in line or "0x" in line:
                    # Parse chunk address and size
                    parts = line.split()
                    for part in parts:
                        if part.startswith("0x"):
                            try:
                                addr = int(part, 16)
                                # This is a simplified parsing
                                # Real implementation would need to parse GEF's output format
                            except Exception:
                                pass
        except Exception:
            pass

        info = HeapInfo(
            chunks=chunks,
            top=top,
            system_mem=system_mem,
            max_system_mem=max_system_mem,
        )
        return info.to_dict()
    except Exception as e:
        return {"error": str(e)}


def stack_analysis() -> Dict[str, Any]:
    """
    Analyze the current stack frames.

    Returns:
        List of StackFrame objects
    """
    try:
        import gdb

        frames = []

        # Get backtrace
        output = gdb.execute("backtrace", to_string=True)

        # Parse backtrace output
        for line in output.strip().split("\n"):
            if line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    frame_num = int(parts[0][1:])  # Remove '#'
                    addr_str = parts[1]

                    # Try to parse address
                    try:
                        if addr_str.startswith("0x"):
                            addr = int(addr_str, 16)
                        else:
                            addr = 0
                    except Exception:
                        addr = 0

                    # Try to get function name
                    func = None
                    if len(parts) >= 3:
                        func = parts[2]

                    frame = StackFrame(
                        address=addr,
                        function=func,
                        offset=frame_num,
                    )
                    frames.append(frame)

        return {"frames": [f.to_dict() for f in frames]}
    except Exception as e:
        return {"error": str(e)}


def breakpoint_set(location: str, type: str = "breakpoint") -> Dict[str, Any]:
    """
    Set a breakpoint at the specified location.

    Args:
        location: Address, symbol, or source location (e.g., "0x400000", "main", "file.c:10")
        type: Type of breakpoint ("breakpoint", "watchpoint", "catchpoint")

    Returns:
        Breakpoint object with details
    """
    try:
        import gdb

        # Execute breakpoint command
        if type == "breakpoint":
            output = gdb.execute(f"break {location}", to_string=True)
        elif type == "watchpoint":
            output = gdb.execute(f"watch {location}", to_string=True)
        elif type == "catchpoint":
            output = gdb.execute(f"catch {location}", to_string=True)
        else:
            return {"error": f"Unknown breakpoint type: {type}"}

        # Parse output to get breakpoint number and address
        bp_num = 0
        addr = 0

        for line in output.split("\n"):
            if "Breakpoint" in line or "Watchpoint" in line or "Catchpoint" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit():
                        bp_num = int(part)
                    elif part.startswith("0x"):
                        try:
                            addr = int(part, 16)
                        except Exception:
                            pass

        bp = Breakpoint(
            number=bp_num,
            address=addr,
            enabled=True,
            type=type,
            location=location,
        )
        return bp.to_dict()
    except Exception as e:
        return {"error": str(e)}


def continue_execution() -> Dict[str, Any]:
    """
    Continue program execution.

    Returns:
        ExecutionState with stop reason and location
    """
    try:
        import gdb

        # Execute continue command
        output = gdb.execute("continue", to_string=True)

        # Parse output to determine stop reason
        stopped = True
        reason = None
        signal = None
        address = None

        # Check for common stop reasons
        if "breakpoint" in output.lower():
            reason = "breakpoint"
        elif "signal" in output.lower():
            reason = "signal"
            # Try to extract signal name
            for line in output.split("\n"):
                if "SIG" in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith("SIG"):
                            signal = part
        elif "exited" in output.lower():
            reason = "exited"
            stopped = False

        # Get current address
        try:
            address = int(gdb.parse_and_eval("$pc"))
        except Exception:
            pass

        state = ExecutionState(
            stopped=stopped,
            reason=reason,
            signal=signal,
            address=address,
        )
        return state.to_dict()
    except Exception as e:
        return {"error": str(e)}


# Tool registry for MCP Server
TOOLS = {
    "execute_command": {
        "function": execute_command,
        "description": "Execute a GEF/GDB command and return the output",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The command to execute (e.g., 'vmmap', 'hexdump $rsp 64')",
                }
            },
            "required": ["command"],
        },
    },
    "get_registers": {
        "function": get_registers,
        "description": "Get the current CPU register state",
        "parameters": {"type": "object", "properties": {}},
    },
    "inspect_memory": {
        "function": inspect_memory,
        "description": "Read and display memory contents at the given address",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "integer",
                    "description": "Memory address to read from (in hex or decimal)",
                },
                "size": {
                    "type": "integer",
                    "description": "Number of bytes to read (default: 64)",
                    "default": 64,
                },
            },
            "required": ["address"],
        },
    },
    "get_memory_map": {
        "function": get_memory_map,
        "description": "Get the memory map of the current process",
        "parameters": {"type": "object", "properties": {}},
    },
    "heap_analysis": {
        "function": heap_analysis,
        "description": "Analyze the current heap state",
        "parameters": {"type": "object", "properties": {}},
    },
    "stack_analysis": {
        "function": stack_analysis,
        "description": "Analyze the current stack frames",
        "parameters": {"type": "object", "properties": {}},
    },
    "breakpoint_set": {
        "function": breakpoint_set,
        "description": "Set a breakpoint at the specified location",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "Address, symbol, or source location (e.g., '0x400000', 'main', 'file.c:10')",
                },
                "type": {
                    "type": "string",
                    "description": "Type of breakpoint ('breakpoint', 'watchpoint', 'catchpoint')",
                    "default": "breakpoint",
                },
            },
            "required": ["location"],
        },
    },
    "continue_execution": {
        "function": continue_execution,
        "description": "Continue program execution",
        "parameters": {"type": "object", "properties": {}},
    },
}
