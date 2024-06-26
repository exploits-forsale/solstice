# Solstice

A multi-stage PE loader for [@carrot_c4k3](https://twitter.com/carrot_c4k3)'s CollateralDamage Xbox One exploit.

## Project overview

There are four main crates:

1. `shellcode_stage1/` is the stage 1 shellcode that is embedded directly in the GameScript exploit. This is intended to be as small as possible so that less typing is required from a rubber ducky/Flipper if that appraoch is used.
2. `shellcode_stage2/` is read by `shellcode_stage1/` from disk, made executable, and executed. It reads a PE file from disk, specified at `AppData\Local\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState\run.exe`, and manually loads the PE using [rspe](https://github.com/landaire/rspe). This shellcode can be arbitrarily large.
3. `shellcode_utils/` contains common functionality shared between the shellcode stages including function definitions and helpers to retrieve functions at runtime.
4. `src/` (`shellcode_gen`) reads the resulting exe files from `shellcode_stage1/` and `shellcode_stage2/`, applies some patches, and generates a flattened .bin file.

`shellcode_stage1/` and `shellcode_stage2/` have a special `.cargo/config.toml` that merges all PE sections into just a single `.text` section, and ensures there are no external dependencies (i.e. no runtime linkage required). They are `#![no_std]`, `#![no_main]` binaries that resolve every platform function at runtime itself.

![shellcode.exe in pe-bear](./images/show_in_pe_bear.png)

`shellcode_gen/`'s main job is to read the `.text` section and do some patches to make it position-independent. This idea
was from [hasherezade](https://twitter.com/hasherezade)'s project [masm_shc](https://github.com/hasherezade/masm_shc). It has also been modified to output a new GameScript exploit file with the latest `shellcode_stage1/` automatically embedded in it, placed in `outputs/`.

This repo is a heavily modified version of [`b1nhack/rust-shellcode`](https://github.com/b1nhack/rust-shellcode). Thank you to b1nhack for their work.

Unfortunately this project is _not_ a proper cargo workspace because Cargo does not allow you to specify a different profile per-crate in a workspace. See: https://github.com/rust-lang/cargo/issues/8264


## How to build it

**This project has only been built and tested using `x86_64-pc-windows-msvc` on Windows 11. It will likely build on any 64-bit Windows, but has not been tested across different versions.**

1. Clone this repo and its dependencies:

```shell
git clone https://github.com/landaire/rspe.git
git clone https://github.com/landaire/solstice.git
cd solstice
```
2. Ensure rust nightly is installed: `rust toolchain install nightly`
3. Install `just`: https://github.com/casey/just
4. Run:

```
just build-exploit
```

## Credits

- [@carrot_c4k3](https://gist.github.com/carrot-c4k3/10fdb4f3d11ca568f5452bbaefdc20dd) for giving me the PRIVILEGE of writing a PE loader for her exploit
- This repo is a heavily modified version of [`b1nhack/rust-shellcode`](https://github.com/b1nhack/rust-shellcode). Thank you to b1nhack for their work.
- [Thoxy67 for their original rspe lib](https://github.com/Thoxy67/rspe) which I modified.
- [monoxgas/sRDI](https://github.com/monoxgas/sRDI/blob/9fdd5c44383039519accd1e6bac4acd5a046a92c/ShellcodeRDI/ShellcodeRDI.c) [polycone/pe-loader](https://github.com/polycone/pe-loader/blob/master/loader/src/loader/) for their PE loaders which served as a reference to double-check I was doing things right
- [horsicq/XPEViewer](https://github.com/horsicq/XPEViewer) which was useful for viewing data from PEs I was having trouble loading.
