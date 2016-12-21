## Command process-search

`process-search` (aka `ps`) is a convenience command to list and filter process
on the host. It is aimed at making the debugging process a little easier when
targeting forking process (such as tcp/listening daemon that would fork upon new
connection).

Without argument, it will return all processes reachable by user:
```
gef➤  ps
1               root            0.0             0.4             ?           /sbin/init
2               root            0.0             0.0             ?           [kthreadd]
3               root            0.0             0.0             ?           [ksoftirqd/0]
4               root            0.0             0.0             ?           [kworker/0:0]
5               root            0.0             0.0             ?           [kworker/0:0H]
6               root            0.0             0.0             ?           [kworker/u2:0]
7               root            0.0             0.0             ?           [rcu_sched]
8               root            0.0             0.0             ?           [rcuos/0]
9               root            0.0             0.0             ?           [rcu_bh]
10              root            0.0             0.0             ?           [rcuob/0]
11              root            0.0             0.0             ?           [migration/0]
[...]
```

Or to filter with pattern:
```
gef➤  ps bash
22590           vagrant         0.0             0.8             pts/0       -bash
```

`ps` also accepts options:

   * `-s` (for `smart`) will discard a number of process (belonging to different
     user, pattern used as an argument and not command, etc.)
   * `-a` (for `attach`) will automatically attach to the first process found

So, for example, if your targeted process is called `/home/foobar/plop`, but the
existing instance is used through `socat`, like

```
$ socat tcp-l:1234,fork,reuseaddr exec:/home/foobar/plop
```

Every time a new connection is opened to tcp/1234, `plop` will be forked, and
`gef` can easily attach to it with the command

```
gef➤  ps -as plop
```
