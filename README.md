# solstice

A multi-stage PE loader for [@carrot_c4k3](https://twitter.com/carrot_c4k3)'s CollateralDamage Xbox One exploit.

## How to build it

You need [rustup](https://rustup.rs) and [just](https://github.com/casey/just) 1.38 or newer. The builds work on Windows and Linux.

1. Clone this repo:

```shell
git clone https://github.com/exploits-forsale/solstice.git
cd solstice
```
2. Install the pinned Rust toolchain and Windows target from `rust-toolchain.toml`: `rustup toolchain install`
3. Run:

```
just build-exploit
```

All necessary outputs will be in the `outputs/` directory.

The shellcode stages link with `rust-lld`, so they need nothing else. The other Windows binaries (`test_program_rust`, `solstice_daemon`, `shellcode_runner`) need the MSVC CRT and Windows SDK:

- On Windows, install the [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/).
- On Linux, install [cargo-xwin](https://github.com/rust-cross/cargo-xwin). It downloads the CRT and SDK the first time it runs. `solstice_daemon` also needs clang, lld and the LLVM tools for its C dependencies.

If you would like to test on the PC version of GameScript, running the following command will execute `build-exploit` and copy the artifacts to the GameScript directory. This will overwrite its autosave state so all you have to do is click "run code":

```
just generate
```

Currently the stage2 shellcode attempts to open and run `run.exe` out of GameScript's `LocalState` directory. An `args.txt` file can be placed in the same directory contaning the command line string to pass to `run.exe`.

### Running the tests

```
just test
```

This builds every stage and runs them under `shellcode_runner` with `test_program_rust.exe` as `run.exe`. Each test gets its own temporary `LocalState` directory.

On Linux the tests run under [Wine](https://www.winehq.org), which cargo-xwin uses as the test runner. Wine cannot start the loaded image, so the tests that run stage3 only run on Windows. CI runs all of them.

### Alternate build modes

#### Building for network development

**ENSURE THAT A `host_ip.txt` EXISTS IN THE ROOT OF THE REPO THAT POINTS TO THE IP ADDRESS THAT WILL BE HOSTING THE `STAGE2`/`run.exe` DELIVERY SERVER**

1. Build necessary stages with:

```
just generate-dev
```

2. Copy `outputs/gamescript_autosave_network.txt` to GameScript
3. Run the server:

```
# Defaults to using the test_rust_program.exe as run.exe
just run-server

# Optionally use the following command to specify a run.exe
just run-server ./path/to/file.exe
```

#### Building a standalone stage2

```
just build-stage2-embedded ./path/to/run.exe
```

This writes `outputs/stage2_embedded.bin`, a stage2 with `run.exe` compiled into it. It reads nothing from disk, so you can drop it in place of `stage2.bin` or call it from your own stage1.

#### Building with debug output (only works with WinDbg attached)

If testing on PC, you can build in debug mode to get debug output in WinDbg.

1. Build

```
just generate debug
```

2. Run GameScript
3. Attach WinDbg
4. Run the exploit

**If WinDbg is not attached the application will crash**. 

## Project overview

solstice uses a 3 stage loader. stage1 and stage2 can be replaced with custom stages and are **not** unique to Xbox or GameScript.

The stage1 loader *is* intended to work well with GameScript, and the project is intended to provide a streamlined experience with exploitation against GameScript. You can even use your own, better reflective PE loader, but you **may** have issues caused by slight differences between the Xbox SystemOS/UWP post-exploitation and a normal Windows exploitation.

For example:

1. The PEB on Xbox is readonly (but you can change its permissions)
2. kernel32.dll is not loaded by default (kernelbase.dll is!)
3. The filesystem is generally more restricted

The 3-stage loader works as shown in the following diagram:

```
        ┌──────────────────────────┐                                                 
        │ GameScript With Exploit  │                                                 
        │     ┌──────────────┐     │                                                 
 ┌────┐ │     │              │     │                                                 
 │ 1  │ │     │  stage1.bin  │◀─ReadFile/VirtualAlloc─┐                              
 └────┘ │     │              │     │                  │                              
        │     └──────────────┘     │                  │                              
        └──────────────────────────┘                  │                              
                                                      │                              
                                            ┌─────────▼─────────────────────┐        
                                            │ ┌──────────────┐ ┌──────────┐ │        
                                            │ │              │ │          │ │        
                                            │ │  stage2.bin  │ │  run.exe │ │        
                                            │ │              │ │          │ │        
                                            │ └──────────────┘ └──────────┘ │        
                                            │  File System           ▲      │        
                                            └────────────────────────┼──────┘        
                                                                     │               
                                                                Reflective           
      ┌─────────────────────────────────────────────────────┐   PE Loader            
      │ GameScript With Exploit                             │        │               
      │ ┌──────────────┐                ┌──────────────┐    │        │               
┌────┐│ │              │                │              │    │        │               
│ 2  ││ │  stage1.bin  │────invoke()───▶│  stage2.bin  │◀───┼────────┘               
└────┘│ │              │                │              │    │                        
      │ └──────────────┘                └──────────────┘    │                        
      └─────────────────────────────────────────────────────┘                        
                                                                                     
                                                                                     
      ┌─────────────────────────────────────────────────────────────────────────────┐
      │ GameScript With Exploit                                                     │
┌────┐│ ┌──────────────┐                ┌──────────────┐               ┌──────────┐ │
│ 3  ││ │              │                │              │               │          │ │
└────┘│ │  stage1.bin  │────invoke()───▶│  stage2.bin  │───invoke()───▶│  run.exe │ │
      │ │              │                │              │               │          │ │
      │ └──────────────┘                └──────────────┘               └──────────┘ │
      └─────────────────────────────────────────────────────────────────────────────┘
```

### `shellcode_stage1`

`shellcode_stage1/` is the stage1 shellcode that is embedded directly in the GameScript exploit. This is intended to be as small as possible so that less typing is required from a Rubber Ducky/Flipper if that approach is used. Additionally, GameScript tends to hit parsing errors if the shellcode array has too many elements so we _must_ keep this stage small.

stage1 loads stage2 from disk, maps it into memory, and executes it.

### `shellcode_stage1_network`

This works basically the same as `shellcode_stage`, but works by opening a socket to a remote server and loading stage2 and stage3 over the network.

stage2 is executed directly in-memory, but the `run.exe` (stage3) _is_ written to disk. Since the same stage2 is shared across non-network and network-based payloads, it makes things easier to load things in the same manner after stage1.

### `shellcode_stage2`

`shellcode_stage2/` is read by stage1 from disk, made executable, and executed. stage2 then reads a PE file from disk, specified at `AppData\Local\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState\run.exe`, and manually loads the PE using our `solstice_loader`. This shellcode can be arbitrarily large since it's not limited by typing or GameScript sizes.

### `solstice_loader`

The main reflective PE loader. This is a fork of [`Thoxy67/rspe`](https://github.com/Thoxy67/rspe) that's been heavily modified.

### `payload_server`

The server that communicates with `shellcode_stage1_network` over port 8080. Its purpose is to send 4 main TCP packets:

1. `stage2` length (4 bytes)
2. `stage2.bin`
3. `run.exe` length (4 bytes)
4. `run.exe`

On port `8081` it can listen for text-based content and print out to the terminal.

### `shellcode_utils`

`shellcode_utils/` contains common functionality shared between the shellcode stages including function definitions and helpers to retrieve functions at runtime.

### `shellcode_gen`

Reads the resulting exe files from `shellcode_stage*/` and generates a flattened .bin file containing only the `.text` section. If the entry point is not at the start of `.text`, a jump to it is placed in front of the code.

### `shellcode_runner`

A Windows test harness that maps a flattened stage into executable memory and calls it like the previous stage would. `just test` uses it to run the stages.

### `solstice_daemon`

Changes firewall settings on the Xbox to allow traffic on port 22 and runs an SSH/SFTP server.

### General

`shellcode_stage1/`, `shellcode_stage1_network`, and `shellcode_stage2/` have a special `.cargo/config.toml` that merges almost all PE sections into just a single `.text` section, and ensures there are no external dependencies (i.e. no runtime linkage required). They are `#![no_std]`, `#![no_main]` binaries that resolve every platform function at runtime itself.

![shellcode.exe in pe-bear](./images/show_in_pe_bear.png)

`shellcode_gen/`'s main job is to extract the `.text` section and make it callable at offset 0. This idea
was from [hasherezade](https://twitter.com/hasherezade)'s project [masm_shc](https://github.com/hasherezade/masm_shc). It has also been modified to output a new GameScript exploit file with the latest `shellcode_stage1/` automatically embedded in it, placed in `outputs/`.

This repo is a heavily modified version of [`b1tg/rust-windows-shellcode`](https://github.com/b1tg/rust-windows-shellcode). Thank you to b1tg for their work.

Unfortunately this project is _not_ a proper cargo workspace because Cargo does not allow you to specify a different profile per-crate in a workspace. See: https://github.com/rust-lang/cargo/issues/8264.

## Why write your own PE loader?

Because I could. And I know how to build/debug/deploy my own code better than an off-the-shelf project. The PE loader is certainly not as mature as others, but it works for our purposes.

## Credits

- [@carrot_c4k3](https://gist.github.com/carrot-c4k3/10fdb4f3d11ca568f5452bbaefdc20dd) for the GameScript and ntkernel exploits.
- This repo is a heavily modified version of [`b1tg/rust-windows-shellcode`](https://github.com/b1tg/rust-windows-shellcode). Thank you to b1tg for their work.
- [Thoxy67 for their original rspe lib](https://github.com/Thoxy67/rspe) which was modified.
- [monoxgas/sRDI](https://github.com/monoxgas/sRDI/blob/9fdd5c44383039519accd1e6bac4acd5a046a92c/ShellcodeRDI/ShellcodeRDI.c) [polycone/pe-loader](https://github.com/polycone/pe-loader/blob/master/loader/src/loader/) for their PE loaders which served as a reference to double-check I was doing things right
- [horsicq/XPEViewer](https://github.com/horsicq/XPEViewer) which was useful for viewing data from PEs I was having trouble loading.
- [0xC0ffee1/sessio](https://github.com/0xC0ffee1/sessio) which has a ready-to-use PTY Shell impl, used in the daemon-crate.
