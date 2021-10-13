# Screenshots

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

This page illustrates a few of the possibilities available to you when using `GEF`.

## Multi-architecture support

`GEF` was designed to support any architecture supported by GDB via an easily extensible architecture API.

Currently `GEF` supports the following architectures:

 - Intel x86 (32b & 64b)
 - ARM (v6/v7)
 - AARCH64
 - MIPS/MIPS64
 - PowerPC
 - SPARC/SPARCv9

## Features

### Embedded hexdump view

To this day, GDB doesn't come with a hexdump-like view. Well `GEF` fixes that for you via the `hexdump` command:

![hexdump](https://i.imgur.com/qt77lFQ.png)

### Dereferencing data or registers

No more endless manual pointer dereferencing `x/x` style. Just use `dereference` for that. Or for a comprehensive view of the registers, `registers` might become your best friend:

![mipsel-deref-regs](https://i.imgur.com/f5ZaWDC.png)

### Heap analysis

#### Detailed view of Glibc Chunks

![x86-heap-chunks](https://i.imgur.com/zBSTUHb.png)

#### Automatic detection of UaF during runtime

![x86-heap-helper-uaf](https://i.imgur.com/NfV5Cu9.png)

### Display ELF information

#### ELF structure

![elf-info](https://i.imgur.com/AkWhJ3t.png)

#### Security settings

![elf-checksec](https://i.imgur.com/HXcwr2S.png)

### Automatic vulnerable string detection

![aarch64-fmtstr](https://i.imgur.com/iF4l1R5.png)

### Code emulation with Unicorn-Engine (x86-64)

![emu](https://i.imgur.com/n4Oy5D0.png)

### Comprehensive address space layout display

![vmmap](https://i.imgur.com/V9zMLUt.png)

### Defining arbitrary custom structures

![sparc-arb-struct](https://i.imgur.com/dEMUuP7.png)

### Highlight custom strings

![highlight-command](https://i.imgur.com/UwSPXrV.png)
