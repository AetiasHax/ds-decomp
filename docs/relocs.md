# `relocs.txt`
This document describes how a `relocs.txt` file is structured.

## Format
Each line in `relocs.txt` is one relocation, and has the following format:
```
from:FROM kind:KIND to:TO add:ADD module:MODULE
```
- `FROM`: Any 32-bit address in this module.
- [`KIND`](#relocation-kinds)
- `TO`: Any 32-bit address in the game's code.
- (optional) `ADD`: Explicit addend to add to the `TO` address.
- [`MODULE`](#destination-module)

### Relocation kinds
- `arm_call`: ARM call to ARM.
- `thumb_call`: Thumb call to Thumb.
- `arm_call_thumb`: ARM call to Thumb.
- `thumb_call_arm`: Thumb call to ARM. 
- `arm_branch`: ARM branch to ARM.
- `load`: 32-bit absolute pointer.
- `overlay_id`: Overlay ID.
    - Special case of `load` that resolves to an overlay ID.
    - The relocation must also have `module:none`.

### Destination module
- `none`: No destination symbol found due to poor analysis by `dsd init`. Many `dsd` subcommands will fail.
- `overlay(X)`: Destination module is in overlay X.
- `overlays(X,Y,Z,...)`: Destination module is in one of many overlays. `dsd delink` will choose the first one in this list.
- `main`: Destination symbol is in the main module.
- `itcm`: Destination symbol is in ITCM.
- `dtcm`: Destination symbol is in DTCM.
