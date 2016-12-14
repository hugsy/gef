## Command config ##

`gef` can also be configured at runtime through a configuration file locate at
`~/.gef.rc`.

To view all the defined settings for all commands loaded:
```
gef➤  gef config
```

To save the current settings for `GEF` on the file system to have those options
saved across all your future `GEF` sessions, simply run:
```
gef➤  gef save
[+] Configuration saved to '/home/vagrant/.gef.rc'
```

And to load settings
```
gef➤  gef restore
[+] Configuration from '/home/vagrant/.gef.rc' restored
```

You can then tweak this configuration outside your `gdb` session to suit your
needs.
