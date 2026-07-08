"""
Data models for GEF MCP Server

These models define the structured output format for MCP tools,
ensuring consistent JSON responses for AI Agent consumption.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RegisterState:
    """CPU register state."""
    registers: Dict[str, int]
    pc: int = 0
    sp: int = 0
    flags: Optional[Dict[str, bool]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registers": {k: hex(v) if isinstance(v, int) else v for k, v in self.registers.items()},
            "pc": hex(self.pc),
            "sp": hex(self.sp),
            "flags": self.flags,
        }


@dataclass
class MemoryContent:
    """Memory content with hex and ASCII representation."""
    address: int
    data: bytes
    ascii_repr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "hex": self.data.hex(),
            "ascii": self.ascii_repr,
            "size": len(self.data),
        }


@dataclass
class MemoryRegion:
    """Memory region information."""
    start: int
    end: int
    size: int
    permissions: str
    name: str = ""
    offset: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.size,
            "permissions": self.permissions,
            "name": self.name,
            "offset": hex(self.offset),
        }


@dataclass
class HeapChunk:
    """Heap chunk information."""
    address: int
    size: int
    prev_size: int = 0
    flags: str = ""
    fd: int = 0
    bk: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "size": self.size,
            "prev_size": self.prev_size,
            "flags": self.flags,
            "fd": hex(self.fd),
            "bk": hex(self.bk),
        }


@dataclass
class HeapInfo:
    """Heap state information."""
    chunks: List[HeapChunk] = field(default_factory=list)
    top: int = 0
    system_mem: int = 0
    max_system_mem: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunks": [c.to_dict() for c in self.chunks],
            "top": hex(self.top),
            "system_mem": self.system_mem,
            "max_system_mem": self.max_system_mem,
        }


@dataclass
class StackFrame:
    """Stack frame information."""
    address: int
    function: Optional[str] = None
    offset: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "function": self.function,
            "offset": self.offset,
        }


@dataclass
class Breakpoint:
    """Breakpoint information."""
    number: int
    address: int
    enabled: bool = True
    type: str = "breakpoint"
    location: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "number": self.number,
            "address": hex(self.address),
            "enabled": self.enabled,
            "type": self.type,
            "location": self.location,
        }


@dataclass
class ExecutionState:
    """Program execution state."""
    stopped: bool
    reason: Optional[str] = None
    signal: Optional[str] = None
    address: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stopped": self.stopped,
            "reason": self.reason,
            "signal": self.signal,
            "address": hex(self.address) if self.address is not None else None,
        }


@dataclass
class CommandResult:
    """Command execution result."""
    output: str = ""
    error: str = ""
    return_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "output": self.output,
            "error": self.error,
            "return_code": self.return_code,
        }
