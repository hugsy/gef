## Command ida-interact ##

`gef` provides a simple XML-RPC client designed to communicate with a server
running inside a specific IDA Python plugin, called `ida_gef.py` (which
can be downloaded freely
[here](https://raw.githubusercontent.com/hugsy/gef/master/scripts/ida_gef.py)).

Simply download this script, and run it inside IDA. When the server is running,
you will see a text in the Output Window such as:

```
[+] Creating new thread for XMLRPC server: Thread-1
[+] Starting XMLRPC server: 0.0.0.0:1337
[+] Registered 6 functions.
```

This indicates that the XML-RPC server is ready and listening.

`gef` can interact with it via the command `ida-interact`. This command receives
as first argument the name of the function to execute, all the other arguments
are the arguments of the remote function.

To enumerate the functions available, simply run
```
gef➤  ida-interact -h
```
![gef-ida-help](https://i.imgur.com/JFNBfjY.png)

Now, to execute an RPC, invoke the command `ida-interact` on the desired method,
with its arguments (if required).

For example:
```
gef➤  ida ida.set_color 0x40061E
```
will edit the remote IDB and set the background color of the location 0x40061E
with the color 0x005500 (default value).

Another convenient example is to add comment inside IDA directly from `gef`:
```
gef➤  ida ida.add_comment 0x40060C "<<<--- stack overflow"
[+] Success
```

Result:

![gef-ida-example](https://i.imgur.com/jZ2eWG4.png)

Please use the `--help` argument to see all the methods available and their
syntax.

It is also note-worthy that [Binary Ninja](https://binary.ninja) support has be added:
![](https://pbs.twimg.com/media/CzSso9bUAAArL1f.jpg:large), by using the
script
[`binja_gef.py`](https://raw.githubusercontent.com/hugsy/gef/master/scripts/binja_gef.py).
