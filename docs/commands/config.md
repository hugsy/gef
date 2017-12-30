## Command config

`gef` can also be configured at runtime through a configuration file locate at
`~/.gef.rc`.

To view all the defined settings for all commands loaded:
```
gef➤  gef config
```
![gef-config](https://i.imgur.com/bd2ZqsU.png)

Or get one setting value:
```
gef➤  gef config pcustom.struct_path
```

Of course you can edit the values. For example, if you want the screen to be
cleared before displaying the current context when reaching a breakpoing:
```
gef➤  gef config context.clear_screen 1
```

To save the current settings for `GEF` to the file system to have those options
persist across all your future `GEF` sessions, simply run:
```
gef➤  gef save
[+] Configuration saved to '/home/vagrant/.gef.rc'
```

Upon startup, if `gef` finds a file `${HOME}/.gef.rc`, it will automatically
loads its values.

To reload the settings during the session, just run:
```
gef➤  gef restore
[+] Configuration from '/home/hugsy/.gef.rc' restored
```

You can tweak this configuration file outside your `gdb` session to suit your
needs.
