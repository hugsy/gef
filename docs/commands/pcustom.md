## Command pcustom ##

`gef` provides a way to create and apply to the currently debugged environment, any new structure (in the C-struct way). On top of simply displaying known and user-defined structures, it also allows to apply those structures to the current context. It intends to mimic the very useful [WinDBG `dt`](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542772(v=vs.85).aspx) command.

This is achieved via the command `pcustom` (for `print custom`), or you can use its alias, `dt` (in reference to the WinDBG command) as provided by the [`WinDbg compatibility extension`](https://github.com/hugsy/gef-extras/blob/master/scripts/windbg.py)


### Configuration

New structures can be stored in the location given by the configuration setting:
```
gef➤ gef config pcustom.struct_path
```
By default, this location is in `$TEMP/gef/structs` (e.g. `/tmp/user/1000/gef/structs`). The structure can be created as a simple `ctypes` structure, in a file called `<struct_name>.py`.

You can naturally set this path to a new location
```
gef➤ gef config pcustom.struct_path /my/new/location
```
And save this change so you can re-use it directly next time you use `gdb`
```
gef➤ gef save
[+] Configuration saved to '~/.gef.rc'
```


### Using user-defined structures

You can list existing custom structures via
```
gef➤  pcustom list
[+] Listing custom structures from '/tmp/structs'
 →  /tmp/structs/A.py (A, B)
 →  /tmp/structs/elf32_t.py (elf32_t)
 →  /tmp/structs/elf64_t.py (elf64_t)
[...]
```

To create or edit a structure, use `pcustom edit <struct_name>` to spawn your EDITOR with the targeted structure. If the file does not exist, `gef` will nicely create the tree and file, and fill it with a `ctypes` template that you can use straight away!

```
gef➤  pcustom new mystruct_t
[+] Creating '/tmp/gef/structs/mystruct_t.py' from template
```

If the structure already exists, GEF will open the text editor to edit the known structure. This is equivalent to:

```
gef➤  pcustom edit elf32_t
[+] Editing '/home/hugsy/code/gef-extras/structs/elf32_t.py'
```



The code can be defined just as any Python (using `ctypes`) code.

```
from ctypes import *

'''
typedef struct {
  int age;
  char name[256];
  int id;
} person_t;
'''

class person_t(Structure):
    _fields_ = [
        ("age",  c_int),
        ("name", c_char * 256),
        ("id", c_int),
    ]

    _values_ = [
    	# You can define a function to substitute the value
    	("age", lambda age: "Old" if age > 40 else "Young"),
    	# Or alternatively a list of 2-tuples
    	("id", [
    		(0, "root"),
    		(1, "normal user"),
    		(None, "Invalid person")
    	])
    ]
```

`pcustom` requires at least one argument, which is the name of the structure. With only one argument, `pcustom` will dump all the fields of this structure.

```
gef➤  dt person_t
+0000   age          c_int   /* size=0x4 */
+0004   name         c_char_Array_256   /* size=0x100 */
+0104   id           c_int   /* size=0x4 */
```



By providing an address or a GDB symbol, `gef` will apply this user-defined structure to the specified address:

![gef-pcustom-with-address](https://i.imgur.com/vWGnu5g.png)

This means that we can now create very easily new user-defined structures

For a full demo, watch the following tutorial:

[![yt-gef-pcustom](https://img.youtube.com/vi/pid2aW7Bt_w/0.jpg)](https://www.youtube.com/watch?v=pid2aW7Bt_w)

Additionally, if you have successfully configured your IDA settings (see command `ida-interact`), you can also directly import the structure(s) that was(were) reverse-engineered in IDA directly in your GDB session:
![ida-structure-examples](https://i.imgur.com/Tnsf6nt.png)

And then use the command `ida ImportStructs` to import all the structures, or `ida ImportStruct <StructName>` to only import a specific one:

```
gef➤  ida ImportStructs
[+] Success
```

Which will become:

![ida-structure-imported](https://i.imgur.com/KVhyopO.png)


### Public repository of structures

A community contributed repository of structures can be found in [`gef-extras`](https://github.com/hugsy/gef-extras). To deploy it:

In bash:
```
$ git clone https://github.com/hugsy/gef-extras
```

In GEF:
```
gef➤ gef config pcustom.struct_path /path/to/gef-extras/structs
gef➤ gef save
```

Then either close GDB or `gef reload`. You can confirm the structures were correctly loaded in GEF's prompt:

```
gef➤ pcustom list
```

Should return several entries.

And remember this is collaborative repository, so feel free to contribute too!
