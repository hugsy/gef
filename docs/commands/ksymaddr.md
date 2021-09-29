## Command ksymaddr ##

`ksymaddr` helps locate a kernel symbol by its name.

The syntax is straight forward:

```
ksymaddr <PATTERN>
```

For example,

```
gef➤  ksymaddr commit_creds
[+] Found matching symbol for 'commit_creds' at 0xffffffff8f495740 (type=T)
[*] Found partial match for 'commit_creds' at 0xffffffff8f495740 (type=T): commit_creds
[*] Found partial match for 'commit_creds' at 0xffffffff8fc71ee0 (type=R): __ksymtab_commit_creds
[*] Found partial match for 'commit_creds' at 0xffffffff8fc8d008 (type=r): __kcrctab_commit_creds
[*] Found partial match for 'commit_creds' at 0xffffffff8fc9bfcd (type=r): __kstrtab_commit_creds
```

Note that the debugging process needs to have the correct permissions for this
command to show kernel addresses. For more information see
also [this stackoverflow post](https://stackoverflow.com/a/55592796).