## Command patch ##

Patch the specified values to the specified address.

This command is automatically aliased to the standard WinDBG commands: `eb`,
`ew`, `ed`, `eq`, and `ea`.

```bash
gef➤ patch byte $eip 0x90
gef➤ eb 0x8048000 0x41
gef➤ ea 0xbffffd74 "This is a double-escaped string\\x00"
```

