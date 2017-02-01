## Command canary

If the currently debugged process was compiled with the Smash Stack Protector
(SSP) - i.e. `-fstack-protector` flag was passed to the compiler, this command
will allow to display the value of the canary. This makes it
convenient when searching for this value in memory.

The command `canary` does not take any argument.
```
gef➤ canary
```

![](https://i.imgur.com/kPmsod2.png)
