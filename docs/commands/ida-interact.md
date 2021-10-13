## Command ida-interact ##

`gef` provides a simple XML-RPC client designed to communicate with a server
running inside a specific IDA Python plugin, called `ida_gef.py` (which
can be downloaded freely
[here](https://raw.githubusercontent.com/hugsy/gef/master/scripts/ida_gef.py)).

Simply download this script, and run it inside IDA. When the server is running,
you should see some output:

```
[+] Creating new thread for XMLRPC server: Thread-1
[+] Starting XMLRPC server: 0.0.0.0:1337
[+] Registered 12 functions.
```

This indicates that IDA is ready to work with `gef`!

`gef` can interact with it via the command `ida-interact` (alias `ida`). This
command expects the name of the function to execute as the first argument, all the
other arguments are the arguments of the remote function.

To enumerate the functions available, simply run
```
gef➤  ida-interact -h
```
![gef-ida-help](https://i.imgur.com/JFNBfjY.png)

Now, to execute an RPC, invoke the command `ida-interact` on the desired method,
with its arguments (if required).

For example:
```
gef➤  ida setcolor 0x40061E
```
will edit the remote IDB and set the background color of the location 0x40061E
with the color 0x005500 (default value).

Another convenient example is to add comment inside IDA directly from `gef`:
```
gef➤  ida makecomm 0x40060C "<<<--- stack overflow"
[+] Success
```

Result:

![gef-ida-example](https://i.imgur.com/jZ2eWG4.png)

Please use the `-h` argument to see all the methods available and their syntax.

It is also note-worthy that [Binary Ninja](https://binary.ninja) support has be added:
![](https://pbs.twimg.com/media/CzSso9bUAAArL1f.jpg:large), by using the
Binary Ninja plugin [`gef-binja.py`](https://github.com/hugsy/gef-binja).
