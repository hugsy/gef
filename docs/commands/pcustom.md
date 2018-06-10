## Command pcustom ##

`gef` provides a way to create and apply to the currently debugged environment,
any new structure (in the C-struct way). On top of simply displaying known
and user-defined structures, it also allows to apply those structures to the
current context. It intends to mimic the very useful
[WinDBG `dt`](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542772(v=vs.85).aspx)
command.

This is achieved via the command `pcustom` (for `print custom`), or you can use
its alias, `dt` (in reference to the WinDBG command).

### Configuration

New structures can be stored in the location given by the configuration setting:
```
gef➤ gef config pcustom.struct_path
```
By default, this location is in `$TEMP/gef/structs` (e.g. `/tmp/user/1000/gef/structs`).
The structure can be created as a simple `ctypes` structure, in a file called
`<struct_name>.py`.

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
gef➤  dt -l
[+] Listing custom structures:
 →  struct5
 →  struct6
```

To create or edit a structure, use `dt <struct_name> -e` to spawn your EDITOR
with the targeted structure. If the file does not exist, `gef` will nicely
create the tree and file, and fill it with a `ctypes` template that you can use
straight away!
```
gef➤  dt mystruct_t -e
[+] Creating '/tmp/gef/structs/mystruct_t.py' from template
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

`pcustom` requires at least one argument, which is the name of the
structure. With only one argument, `pcustom` will dump all the fields of this
structure.

```
gef➤  dt person_t
+0000 age c_int (0x4)  →  Young
+0004 name c_char_Array_256 (0x100)
+0104 id c_int (0x1)   →  normal user
```



By providing an address or a GDB symbol, `gef` will apply this user-defined
structure to the specified address:

![gef-pcustom-with-address](https://i.imgur.com/vWGnu5g.png)

This means that we can now create very easily new user-defined structures

Watch the demonstration video on Asciinema:

[![asciicast](https://asciinema.org/a/bhsguibtf4iqyyuomp3vy8iv2.png)](https://asciinema.org/a/bhsguibtf4iqyyuomp3vy8iv2)

Additionally, if you have successfully configured your IDA settings (see command
`ida-interact`), you can also directly import the structure(s) that was(were)
reverse-engineered in IDA directly in your GDB session:

![ida-structure-examples](https://i.imgur.com/Tnsf6nt.png)

And then use the command `ida ImportStructs` to import all the structures, or
`ida ImportStruct <StructName>` to only import a specific one:

```
gef➤  ida ImportStructs
[+] Success
```

Which will become:

![ida-structure-imported](https://i.imgur.com/KVhyopO.png)

