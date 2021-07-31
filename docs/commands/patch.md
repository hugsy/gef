## Command patch ##

`patch` lets you easily patch the specified values to the specified address.

```bash
gef➤ patch byte $eip 0x90
gef➤ patch string $eip "cool!"
```

