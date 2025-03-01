# `delinks.txt`
This document describes how a `delinks.txt` file is structured.

## Contents
- [Format](#format)
    - [Module](#module)
        - [Section kinds](#section-kinds)
    - [Files](#files)
        - [File options](#file-options)
- [Example](#example)

## Format
```
MODULE

FILES
```
Notice the blank line between the module and files!

- [`MODULE`](#module)
- [`FILES`](#files)

Example:

### Module
Goes at the top of the file. These are the sections of the entire module.

```
    SECTION start:START end:END kind:KIND align:ALIGN
    SECTION start:START end:END kind:KIND align:ALIGN
    ...
```
Notice the indentation on the lines above!

- `SECTION`: The section's name, such as `.text`, `.data` or `.bss`.
- `START`: Any 32-bit address aligned to `ALIGN`.
- `END`: Any 32-bit address greater than `START`.
- [`KIND`](#section-kinds)
- `ALIGN`: Any power of two.

#### Section kinds
- `code`: Contains mostly code and some data
- `data`: Contains only data
- `rodata`: Contains read-only data
- `bss`: Contains only uninitialized data

### Files
```
PATH:
    OPTION
    OPTION
    ...
    SECTION start:START end:END
    SECTION start:START end:END
    ...

PATH:
    ...
```

- `PATH`: A relative file path to the source file..
    - `dsd delink` will append this path to `delinks_path` (from `config.yaml`) when creating delinked objects. The file extension will be changed to `.o`.
    - `dsd lcf` will do the same when generating the linker script. If this file is marked as `complete`, it will append the path to `build_path` instead.
- [`OPTION`](#file-options)
- `SECTION`: The name of a section among [those in the module](#module).
- `START`: Any aligned 32-bit address.
- `END`: Any 32-bit address greater than `START`.

The files may appear in any order, `dsd lcf` will handle the link order automatically.

#### File options
- `complete`: This file has been fully decompiled. `dsd lcf` will pass this decompiled file to the linker instead of the delinked file.

## Example
```
    .text       start:0x020773c0 end:0x020d8770 kind:code align:32
    .rodata     start:0x020d8770 end:0x020df338 kind:rodata align:4
    .init       start:0x020df338 end:0x020e1e88 kind:code align:4
    .ctor       start:0x020e1e88 end:0x020e1f6c kind:rodata align:4
    .data       start:0x020e1f80 end:0x020e9320 kind:data align:32
    .bss        start:0x020e9320 end:0x020eed40 kind:bss align:32

src/00_Core/Actor/Actor.cpp:
    .text       start:0x020c1500 end:0x020c3348
    .rodata     start:0x020dd370 end:0x020dd3f8
    .data       start:0x020e71a0 end:0x020e72a8

src/00_Core/Actor/ActorManager.cpp:
    complete
    .text       start:0x020c33d4 end:0x020c3e54
    .data       start:0x020e72a8 end:0x020e72f4

src/00_Core/Item/Item.cpp:
    .text       start:0x020ad020 end:0x020ad090
    .rodata     start:0x020dc574 end:0x020dc6c4
```
