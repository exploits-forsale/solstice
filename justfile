# PowerShell aliases `cp`, so recipes that copy files work under both shells.
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# Std Windows binaries need the MSVC CRT and SDK. cargo-xwin downloads them on other hosts.
win_cargo := if os_family() == "windows" { "cargo" } else { "cargo xwin" }
win_target := "x86_64-pc-windows-msvc"
host_exe := if os_family() == "windows" { ".exe" } else { "" }

outputs := justfile_directory() / "outputs"
gamescript_state := env("LOCALAPPDATA", "") / "Packages/27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522/LocalState"

default_features := ""
default_run := outputs / "test_program_rust.exe"

[unix]
outputs-dir:
    mkdir -p "{{outputs}}"

[windows]
outputs-dir:
    New-Item -ItemType Directory -Force "{{outputs}}" | Out-Null

[working-directory: 'crates/shellcode_stage1']
build-stage1 features=default_features:
    cargo build --release --features={{features}}

[working-directory: 'crates/shellcode_stage1_network']
build-stage1-network features=default_features:
    cargo build --release --features={{features}}

[working-directory: 'crates/shellcode_stage2']
build-stage2 features=default_features:
    cargo build --release --features={{features}}

# Builds every stage and writes the flattened stages and GameScript exploits to outputs/.
[working-directory: 'crates/shellcode_gen']
build-exploit features=default_features: (build-stage1 features) (build-stage1-network features) (build-stage2 features)
    cargo run --release -- "{{outputs}}"

# Builds a stage2 that loads `image` from itself instead of disk. Writes outputs/stage2_embedded.bin.
[working-directory: 'crates/shellcode_gen']
build-stage2-embedded image features=default_features: outputs-dir (compile-stage2-embedded join(invocation_directory_native(), image) features)
    cargo run --release -- flatten ../shellcode_stage2/target/embedded/{{win_target}}/release/shellcode_stage2.exe "{{outputs}}/stage2_embedded.bin"

# include_bytes! resolves relative paths against the source file, so the image path is absolute.
[private]
[working-directory: 'crates/shellcode_stage2']
compile-stage2-embedded $SOLSTICE_EMBEDDED_IMAGE features:
    cargo build --release --features=embedded_image,{{features}} --target-dir target/embedded

[working-directory: 'crates/test_program_rust']
build-test-program-rust features=default_features: outputs-dir
    {{win_cargo}} build --release --target {{win_target}} --features={{features}}
    cp target/{{win_target}}/release/test_program_rust.exe "{{outputs}}/"

[working-directory: 'crates/payload_server']
build-server features=default_features: outputs-dir
    cargo build --release --features={{features}}
    cp target/release/payload_server{{host_exe}} "{{outputs}}/"

[working-directory: 'crates/solstice_daemon']
build-daemon features=default_features: outputs-dir
    {{win_cargo}} build --release --target {{win_target}} --features={{features}}
    cp target/{{win_target}}/release/solstice_daemon.exe "{{outputs}}/srv.exe"

[working-directory: 'crates/payload_server']
run-server run=default_run features=default_features:
    cargo run --release --features={{features}} -- --stage2 "{{outputs}}/stage2.bin" --run "{{join(invocation_directory_native(), run)}}"

# Runs the stages under shellcode_runner. Other hosts need Wine, which cargo-xwin uses as the
# test runner. Wine cannot run the loaded image, so those tests only run on Windows.
[working-directory: 'crates/shellcode_runner']
test: build-exploit build-test-program-rust (build-stage2-embedded default_run)
    {{win_cargo}} test --release --target {{win_target}} {{ if os_family() == "windows" { "" } else { "-- --skip runs_image" } }}

# Copies the exploit to the PC version of GameScript, replacing its autosave.
[windows]
generate features=default_features: (build-exploit features) (build-test-program-rust features)
    cp "{{outputs}}/stage2.bin" "{{gamescript_state}}/stage2.bin"
    cp "{{outputs}}/test_program_rust.exe" "{{gamescript_state}}/test_program_rust.exe"
    cp "{{outputs}}/gamescript_autosave.txt" "{{gamescript_state}}/gamescript_autosave.txt"

[windows]
generate-dev features=default_features: (build-exploit features) (build-test-program-rust ("network," + features))
    cp "{{outputs}}/stage2.bin" "{{gamescript_state}}/stage2.bin"
    cp "{{outputs}}/test_program_rust.exe" "{{gamescript_state}}/test_program_rust.exe"
    cp "{{outputs}}/gamescript_autosave_network.txt" "{{gamescript_state}}/gamescript_autosave.txt"

prepare-for-deployment: build-exploit build-server (build-daemon "firewall")
