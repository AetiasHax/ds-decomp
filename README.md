# ds-decomp
Toolkit for decompiling DS games, `dsd` for short.

Join the discussion in the `#dsd` channel of our [Discord server](https://discord.gg/gwN6M3HQrA)!

## Contents
- [Goals](#goals)
- [Commands](#commands)
    - [`rom extract`](#rom-extract)
    - [`rom build`](#rom-build)
    - [`rom config`](#rom-config)
    - [`init`](#init)
    - [`delink`](#delink)
    - [`dis`](#dis)
    - [`objdiff`](#objdiff)
    - [`lcf`](#lcf)
    - [`json delinks`](#json-delinks)
    - [`check modules`](#check-modules)
    - [`check symbols`](#check-symbols)
    - [`apply`](#apply)
    - [`sig apply`](#sig-apply)
    - [`sig list`](#sig-list)

## Goals
- Automate decomp project setup with zero user input, saving months of manual setup time.
- Allow developers to easily delink code into individual translation units and to quickly give names to symbols.
- Generate linker scripts with correct link order.
- Integrate with other decompilation tools, including [objdiff](https://github.com/encounter/objdiff).

## Commands

### `rom extract`

Extracts a DS ROM into separate files for code and assets.

```shell
$ dsd rom extract --rom path/to/rom.nds --output-path path/to/extract/
```

Options:
- `-r`, `--rom`: Path to ROM file.
- `-7`, `--arm7-bios`: Path to ARM7 BIOS file, needed for decryption.
- `-o`, `--output-path`: Path to extract directory.

### `rom build`

Builds a DS ROM from an extract directory.

```shell
$ dsd rom build --config path/to/extract/config.yaml --rom path/to/built_rom.nds
```

Options:
- `-c`, `--config`: Path to `config.yaml` in the extract directory.
- `-7`, `--arm7-bios`: Path to ARM7 BIOS file, needed for encryption.
- `-o`, `--rom`: Path to ROM file.

### `rom config`

Creates a `ds-rom` configuration to build a ROM from linked binaries.

```shell
$ dsd rom config --elf path/to/final_link.o --config path/to/config.yaml
```

Options:
- `-e`, `--elf`: Path to the final linked ELF file, generated by the LCF and the linker.
- `-c`, `--config`: Path to `config.yaml` generated by [`init`](#init).

### `init`

Initialize a new `dsd` configuration from a given extract directory generated by [`rom extract`](#rom-extract). This will analyze the code and generate config files.

```shell
$ dsd init --rom-config path/to/extract/config.yaml --output-path path/to/output/ --build-path path/to/build/
```

Options:
- `-r`, `--rom-config`: Path to `config.yaml` in the extract directory.
- `-o`, `--output-path`: Output path for `dsd` config files.
- `-d`, `--dry`: Dry run, only perform analysis but don't write any files.
- `-b`, `--build-path`: Output path for delinks and the LCF.

### `delink`

Delinks the game into relocatable ELF files. The output directory is determined by `delinks_path` in `config.yaml`.

```shell
$ dsd delink --config-path path/to/config.yaml
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).

### `dis`

Disassembles the game into assembly files. Used for informational purposes, doesn't target a specific assembler.

```shell
$ dsd dis --config-path path/to/config.yaml --asm-path path/to/asm/
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-a`, `--asm-path`: Output path for assembly files.

### `objdiff`

Generates an `objdiff` configuration.

```shell
$ dsd objdiff --config-path path/to/config.yaml
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-o`, `--output-path`: Path to directory to generate `objdiff.json`.
- `-s`, `--scratch`: Include decomp.me scratches.
- `-C`, `--compiler`: Name of compiler in decomp.me, see https://decomp.me/api/compiler for compilers for the `nds_arm9` platform.
- `-f`, `--c-flags`: Compiler flags, as a single string.
- `-p`, `--preset-id`: Preset ID to use in decomp.me.
- `-m`, `--custom-make`: Custom build command for `objdiff`.
- `-M`, `--custom-args`: Arguments to custom build command. Can be passed multiple times to append more arguments.

### `lcf`

Generates a linker command file (LCF) for `mwldarm`.

```shell
$ dsd lcf --config-path path/to/config.yaml --lcf-file path/to/linker_script.lcf --objects-file path/to/objects.txt
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-l`, `--lcf-file`: Output path to LCF file.
- `-o`, `--objects-file`: Output path to objects list, to be passed to the linker.

### `json delinks`

Meant to be used by build systems. Outputs a JSON-formatted object containing information about which files [`delink`](#delink) generates and files needed for linking.

```shell
$ dsd json delinks --config-path path/to/config.yaml
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).

### `check modules`

Verifies that built modules are matching the base ROM.

```shell
$ dsd check modules --config-path path/to/config.yaml
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-f`, `--fail`: Return failing exit code if a module doesn't pass the checks.

### `check symbols`

Verifies that all symbols from every `symbols.txt` file exist in the final linked ELF file.

```shell
$ dsd check symbols --config-path path/to/config.yaml --elf-path path/to/final_link.o
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-e`, `--elf-path`: Path to the final linked ELF file, generated by the LCF and the linker.
- `-f`, `--fail`: Return failing exit code if a symbol didn't match.

### `apply`

Applies symbol data from the final linked ELF to `symbols.txt` files.

```shell
$ dsd apply --config-path path/to/config.yaml --elf-path path/to/final_link.o
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-e`, `--elf-path`: Path to the final linked ELF file, generated by the LCF and the linker.
- `-d`, `--dry`: Dry run, do not write to any files.
- `-v`, `--verbose`: Verbose output.

### `sig apply`

Searches for a function using a signature. If found, the functions and its related objects get renamed.

```shell
$ dsd sig spply --config-path path/to/config.yaml --all
```

Options:
- `-c`, `--config-path`: Path to `config.yaml` generated by [`init`](#init).
- `-s`, `--signature`: Name of signature to apply.
- `-a`, `--all`: Apply all known signatures.
- `-d`, `--dry`: Dry run, do not write to any files.

### `sig list`

Lists all known signatures that can be applied with [`sig apply`](#sig-apply)

```shell
$ dsd sig list
```
