## Command trace-run ##

The `trace-run` command is meant to be provide a visual appreciation directly
in IDA disassembler of the path taken by a specific execution. It should be
used with the IDA script
[`ida_color_gdb_trace.py`](https://github.com/hugsy/stuff/blob/master/ida_scripts/ida_color_gdb_trace.py)

It will trace and store all values taken by `$pc` during the execution flow,
from its current value, until the value provided as argument.

```
gef> trace-run <address_of_last_instruction_to_trace>
```

![trace-run-1](https://i.imgur.com/yaOGste.png)

By using the script `ida_color_gdb_trace.py` on the text file generated, it will
color the path taken:

![trace-run-2](http://i.imgur.com/oAGoSMQ.png)

