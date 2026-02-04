## Screenshots

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

This page illustrates a few of the possibilities available to you when using `GEF`.

## Multi-architecture support

`GEF` was designed to support any architecture supported by GDB via an easily
extensible architecture API.

Currently `GEF` supports the following architectures:

-  Intel x86 (32b & 64b)
-  ARM (v6/v7)
-  AARCH64
-  MIPS/MIPS64
-  PowerPC
-  SPARC/SPARCv9

## Features

### Embedded hexdump view

To this day, GDB doesn't come with a hexdump-like view. Well `GEF` fixes that for you via the
`hexdump` command:

![hexdump](docs/assets/images/hexdump.png)

### Dereferencing data or registers

No more endless manual pointer dereferencing `x/x` style. Just use `dereference` for that. Or for a
comprehensive view of the registers, `registers` might become your best friend:

![mipsel-deref-regs](docs/assets/images/mipsel-deref-regs.png)

### Heap analysis

#### Detailed view of Glibc Chunks

![x86-heap-chunks](docs/assets/images/x86-heap-chunks.png)

#### Automatic detection of UaF during runtime

![x86-heap-helper-uaf](docs/assets/images/x86-heap-helper-uaf.png)

### Display ELF information

#### ELF structure

![elf-info](docs/assets/images/elf-info.png)

#### Security settings

![elf-checksec](docs/assets/images/elf-checksec.png)

### Automatic vulnerable string detection

![aarch64-fmtstr](docs/assets/images/aarch64-fmtstr.png)

### Code emulation with Unicorn-Engine (x86-64)

![emu](docs/assets/images/emu.png)

### Comprehensive address space layout display

![vmmap](docs/assets/images/vmmap.png)

### Defining arbitrary custom structures

![sparc-arb-struct](docs/assets/images/sparc-arb-struct.png)

### Highlight custom strings

![highlight-command](docs/assets/images/highlight-command.png)
