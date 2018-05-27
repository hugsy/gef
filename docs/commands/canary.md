## Command canary ##

If the currently debugged process was compiled with the Smash Stack Protector
(SSP) - i.e. the `-fstack-protector` flag was passed to the compiler, this
command will display the value of the canary. This makes it convenient to avoid
manually searching for this value in memory.

The command `canary` does not take any arguments.
```
gef➤ canary
```

![gef-canary](https://i.imgur.com/kPmsod2.png)
