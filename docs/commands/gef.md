## Command gef ##

Displays a list of GEF commands and their descriptions.

```
gef➤  gef                                                                             
─────────────────────────────────── GEF - GDB Enhanced Features ───────────────────────────────────
$                         -- SmartEval: Smart eval (vague approach to mimic WinDBG `?`).
aslr                      -- View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not
                             attached). This command allows to change that setting.   
assemble                  -- Inline code assemble. Architecture can be set in GEF runtime config (default x86-32).  (alias: asm)
bincompare                -- BincompareCommand: compare an binary file with the memory position looking for badchars.
bytearray                 -- BytearrayCommand: Generate a bytearray to be compared with possible badchars.
[snip]
```
