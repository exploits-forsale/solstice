# peloader

A reflective PE loader. Based off of [Thoxy67/rspe](https://github.com/Thoxy67/rspe) ([MIT licensed](https://github.com/Thoxy67/rspe/blob/main/LICENSE)).

## Features

- `#![no_std]` compatible
- Can load native PE files
    - [x] 64-bit
    - [x] 32-bit
- .NET PE (C#/VB/CLR...)
    - [ ] 64-bit .NET RunPE into Memory (maybe view [clroxide lib](https://github.com/yamakadi/clroxide))
    - [ ] 32-bit .NET RunPE into Memory (maybe view [clroxide lib](https://github.com/yamakadi/clroxide))
- TLS callbacks
- Imports by ordinal/name
- Support for W^X environments (via `VirtualAlloc` + `VirtualProtect`)
- Attempts to load at the preferred module load address

## Missing Features

- Proper memory protections for sections
- Running the new image in a new thread
