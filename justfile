set shell := ["cmd.exe", "/c"]

default-features := ""

build-stage1 features=default-features:
    cd ./crates/shellcode_stage1 && cargo build --release --features={{features}}

build-stage2 features=default-features:
    cd ./crates/shellcode_stage2 && cargo build --release --features={{features}}

build-test-program features=default-features:
    cd ./crates/test_program && cargo build --release --features={{features}}

build-exploit features=default-features:
    just --justfile {{justfile()}} build-stage1 {{features}}
    just --justfile {{justfile()}} build-stage2 {{features}}
    cd ./crates/shellcode_gen && cargo run --release -- ../../outputs/

generate features=default-features:
    just --justfile {{justfile()}} build-exploit {{features}}
    just --justfile {{justfile()}} build-test-program {{features}}
    xcopy /y crates\\shellcode_stage2\\target\\x86_64-pc-windows-msvc\\release\\shellcode_stage2.bin %LOCALAPPDATA%\\Packages\\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\\LocalState\\stage2.bin
    xcopy /y crates\\test_program\\target\\release\\test_program.exe %LOCALAPPDATA%\\Packages\\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\\LocalState
    xcopy /y outputs\\gamescript_poc.txt %LOCALAPPDATA%\\Packages\\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\\LocalState\\gamescript_autosave.txt
