# Running the Project

## Requirements

To build and run the current version, you need:

* Rust and Cargo;
* a local LibAFL source checkout;
* OpenOCD with RISC-V target support;
* an OpenOCD-compatible debug adapter;
* a supported RISC-V target;
* a target ELF file;
* a `power.txt` file containing the latest measurement value.

The current version does not yet read directly from the power measurement device. The value must be written to `power.txt` by another process.

The full setup has not yet been tested on the final hardware.

## Prepare the LibAFL Dependency

`Cargo.toml` uses local path dependencies:

```toml
libafl = { path = "../LibAFL/crates/libafl", features = ["tui_monitor", "std"] }
libafl_bolts = { path = "../LibAFL/crates/libafl_bolts" }
```
The LibAFL repository must be placed in the same parent folder as the `libafl_fuzzer` project. This is required because `Cargo.toml` uses local paths to access the LibAFL crates.

If LibAFL is stored somewhere else, update the paths in `Cargo.toml` before building.

## Build the Project

Open a terminal in the project folder and check that Rust and Cargo are available:

```powershell
rustc --version
cargo --version
```

Check whether the project compiles:

```powershell
cargo check
```

Build the project with:

```powershell
cargo build
```

For an optimized release build, use:

```powershell
cargo build --release
```

If the build succeeds, the compiled files will be created in the `target` directory.

## Prepare the Target Program

The current code expects the target ELF file at:

`testcases/program.elf`

If the `testcases` folder does not exist, create it first:

```powershell
New-Item testcases -ItemType Directory
```

Then place the required ELF file inside that folder and name it:

`program.elf`

The ELF file must match the RISC-V target used with OpenOCD.

The code sends the relative path `testcases/program.elf` to OpenOCD. Therefore, OpenOCD should also be started from the project folder. Otherwise, OpenOCD may not find the ELF file.

## Prepare the Power Measurement File

The current implementation reads the latest measurement from:

`power.txt`

Create the file in the main project folder:

```powershell
Set-Content power.txt "0.0"
```

The file should contain only one valid numeric value, for example:

```text
2.417
```

At the moment, the Rust program does not communicate directly with the power measurement device. Another process must update `power.txt` with the latest value.

If the file is missing, unreadable or contains an invalid value, the current implementation uses `0.0` without reporting an error.

## Start OpenOCD

OpenOCD must already be running before the Rust program is started.

Start OpenOCD from the main project folder so that it can resolve the relative ELF path.

The exact command depends on the debug adapter and RISC-V target. In general, OpenOCD is started with an interface configuration and a target configuration:

```powershell
openocd -f interface/<interface-config>.cfg -f target/<target-config>.cfg
```

The current Rust code connects to the OpenOCD Tcl interface at:

`127.0.0.1:6666`

The selected OpenOCD configuration must enable the Tcl interface on port `6666`.

The correct interface and target configurations for the final hardware still need to be confirmed.

## Run the Program

After OpenOCD is running and the required files are prepared, open another terminal in the project folder and run:

```powershell
cargo run
```

For an optimized build, use:

```powershell
cargo run --release
```

A successful initial connection and setup should show messages similar to:

```text
Connected to OpenOCD at 127.0.0.1:6666
Loading program: testcases/program.elf
Program loaded successfully.
Idle power: 0.0
Running power: 0.0
```

The exact measurement values depend on the contents of `power.txt`.

## Current Fuzzing Behaviour

The current corpus starts empty. Therefore, the fuzzing loop cannot perform useful iterations until a seed input is added.

The current implementation also uses `NopMutator`, so it does not modify inputs.

Once a seed input and a working mutator are added, the program is intended to print the following when an input produces a new highest measurement:

```text
New best measurement: <value>
```

During an executed iteration, the current input is written to:

`current_input.bin`

The program creates a `solutions/` directory automatically and configures it as the LibAFL solutions corpus. However, the current numeric feedback is configured as normal corpus feedback, so new best-measurement inputs are added to the in-memory corpus and are not currently saved in `solutions/`.

