# `symbols.txt`
This document describes how a `symbols.txt` file is structured.

## Contents
- [Format](#format)
    - [Symbol kinds](#symbol-kinds)
        - [Functions](#functions)
        - [Labels](#labels)
        - [Data](#data)
        - [BSS](#bss)
    - [Symbol attributes](#symbol-attributes)
- [Comments](#comments)

## Format
Each line in `symbols.txt` is one symbol, and has the following format:
```
NAME kind:KIND addr:ADDRESS ATTRIBUTES
```
- `NAME`: Any string without whitespace characters
- [`KIND`](#symbol-kinds)
- `ADDRESS`: Any 32-bit address
- [`ATTRIBUTES`](#symbol-attributes)

### Symbol kinds
- [`function(OPTION,...)`](#functions)
- [`label(OPTION,...)`](#labels)
- [`data(OPTION,...)`](#labels)
- [`bss(OPTION,...)`](#bss)

#### Functions
- Instruction mode: `arm` or `thumb`
- Size: `size=0x1234`
- Unknown function?: `unknown`

Example:
```
main kind:function(arm,size=0x30) addr:0x02000c30
```

#### Labels
- Instruction mode: `arm` or `thumb`

Example:
```
_02002e28 kind:label(arm) addr:0x02002e28
```

#### Data
- Type
    - `any`
    - `byte`, `short` or `word`
        - Array? (suffix): `[]`, `[1234]`

The size of `any` and unbounded arrays such as `byte[]` will be calculated automatically to fill the space between the current
symbol and the next symbol in the same section. If it's the last symbol, it will fill the gap until the end of the section.

Example:
```
_02003154 kind:data(byte[256]) addr:0x02003154
data_02050f54 kind:data(any) addr:0x02050f54
```

#### BSS
- Size?: `size=0x1234`

If the size is not specified, it will be calculated automatically just like [`any` for data symbols](#data).

Example:
```
data_02058e20 kind:bss(size=0x2) addr:0x02058e20
data_02058e22 kind:bss addr:0x02058e22
```

### Symbol attributes
- Local?: `local`
- Ambiguous?: `ambiguous`

A local symbol is only visible to its translation unit and will not cause a duplicate symbol definition error with the linker.

Ambiguous symbols exist solely to resolve ambiguous relocations, where the relocation can lead to one of multiple overlays.

Example:
```
SameSymbolName kind:data(any) addr:0x02001234 local
SameSymbolName kind:data(any) addr:0x02005678 local
AmbiguousSymbol kind:bss addr:0x02009abc ambiguous
```

## Comments
You can write `//` to make a line comment. Anything after the `//` will be ignored by dsd.
