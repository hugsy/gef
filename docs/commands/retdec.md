## Command retdec ##

`gef` uses the RetDec decompilation Web API (https://retdec.com/decompilation)
to decompile parts of or entire binary. The command, `retdec`, also has a
default alias, `decompile` to make it easier to remember.

To use the command, you need to provide `gef` a valid RetDec API key, available
by registering [here](https://retdec.com/registration/) (free accounts).

Then enter the key through the `gef config` command:
```
gef➤ gef config retdec.key 1234-1234-1234-1234
```

You can have `gef` save this key by saving the current configuration settings.
```
gef➤ gef save
```

`retdec` can be used in 3 modes:

   * By providing the option `-a`, `gef` will submit the entire binary being
     debugged to RetDec. For example,
```
gef➤ decompile -a
```
![gef-retdec-full](https://i.imgur.com/PzBXf3U.png)

   * By providing the option `-r START:END`, `gef` will submit only the raw
     bytes contained within the range specified as argument.

   * By providing the option `-s SYMBOL`, `gef` will attempt to reach a specific
     function symbol, dump the function in a temporary file, and submit it to
     RetDec. For example,
```
gef➤ decompile -s main
```
![gef-retdec-symbol-main](https://i.imgur.com/76Yl9iD.png)


