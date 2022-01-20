## Command heap-analysis-helper ##

Please note: This feature is still under development, expect bugs and unstability.

`heap-analysis-helper` command aims to help the process of idenfitying Glibc
heap inconsistencies by tracking and analyzing allocations and deallocations of
chunks of memory.

Currently, the following issues can be tracked:

   * NULL free
   * Use-after-Free
   * Double Free
   * Heap overlap

The helper can simply be activated by running the command `heap-analysis-helper`.

```
gef➤ heap-analysis
[+] Tracking malloc()
[+] Tracking free()
[+] Disabling hardware watchpoints (this may increase the latency)
[+] Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.
[+] To disable, clear the malloc/free breakpoints (`delete breakpoints`) and restore hardware breakpoints (`set can-use-hw-watchpoints 1`)
```

The helper will create specifically crafted breakoints to keep tracks of
allocation, which allows to discover *potential* vulnerabilities. Once
activated, one can disable the heap analysis breakpoints simply by clearing the
`__GI___libc_free()` et `__GI___libc_malloc()`. It is also possible to
enable/disable manually punctual checks via the `gef config` command.

The following settings are accepted:

   * `check_null_free`: to break execution when a free(NULL) is encountered
     (disabled by default);
   * `check_double_free`: to break execution when a double free is encountered;

![double-free](https://i.imgur.com/S7b4FJa.png)

   * `check_weird_free`: to execution when `free()` is called against a
     non-tracked pointer;
   * `check_uaf`: to break execution when a possible Use-after-Free condition is
     found.

![uaf](https://i.imgur.com/NfV5Cu9.png)

Just like the format string vulnerability helper, the `heap-analysis-helper`
can fail to detect complex heap scenarios and/or provide some false positive
alerts. Each finding must of course be ascertained manually.

The `heap-analysis-helper` can also be used to simply track allocation and
liberation of chunks of memory. One can simply enable the tracking by setting
all the configurations stated above to False:

```
gef➤  gef config heap-analysis-helper.check_double_free False
gef➤  gef config heap-analysis-helper.check_free_null False
gef➤  gef config heap-analysis-helper.check_weird_free False
gef➤  gef config heap-analysis-helper.check_uaf False
```

Then `gef` will not notify you of any inconsistency detected, but simply display
a clear message when a chunk is allocated/freed.

![heap-track](https://i.imgur.com/68NGTvw.png)

To get information regarding the currently tracked chunks, use the `show`
subcommand:

```
gef➤  heap-analysis-helper show
```

![heap-analysis-helper-show](https://i.imgur.com/0I4jBWJ.png)
