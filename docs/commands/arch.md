## Command `arch`

`arch` manages the loaded architecture.

There are 3 available sub-commands:

-  `list`: List the installed architectures.
-  `get`: Print the currently loaded architecture, and why it is selected.
-  `set`: Manually set the loaded architecture by providing its name as an argument, or let
  gef do magic to detect the architecture by not providing arguments.

> [!WARNING]
> Setting manually should be done as a last resort as GEF expects to find the architecture
> automatically. Force-setting the architecture can lead to unexpected behavior if not done correctly.


![arch](https://github.com/hugsy/gef/assets/11377623/e364ecec-0b8e-4bee-b3cb-aae83eaca439)
