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

![hexdump](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/hexdump.png)

### Dereferencing data or registers

No more endless manual pointer dereferencing `x/x` style. Just use `dereference` for that. Or for a
comprehensive view of the registers, `registers` might become your best friend:

![mipsel-deref-regs](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/mipsel-deref-regs.png)

### Heap analysis

#### Detailed view of Glibc Chunks

![x86-heap-chunks](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/x86-heap-chunks.png)

#### Automatic detection of UaF during runtime

![x86-heap-helper-uaf](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/x86-heap-helper-uaf.png)

### Display ELF information

#### ELF structure

![elf-info](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/elf-info.png)

#### Security settings

![elf-checksec](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/elf-checksec.png)

### Automatic vulnerable string detection

![aarch64-fmtstr](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/aarch64-fmtstr.png)

### Code emulation with Unicorn-Engine (x86-64)

![emu](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/emu.png)

### Comprehensive address space layout display

![vmmap](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/vmmap.png)

### Defining arbitrary custom structures

![sparc-arb-struct](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/sparc-arb-struct.png)

### Highlight custom strings

![highlight-command](https://raw.githubusercontent.com/hugsy/gef/refs/heads/main/docs/assets/images/highlight-command.png)
