# LibAFL Numeric Fuzzer with OpenOCD Integration

## Project Overview

This project is a prototype LibAFL-based fuzzer that uses a numeric measurement instead of traditional code coverage as feedback.

The intended use case is to generate or mutate inputs for a RISC-V target and maximize a measured value such as power consumption.

The program communicates with the target through the OpenOCD Tcl interface.

## Current Implementation

The current implementation:

* connects to OpenOCD through TCP;
* uses the OpenOCD Tcl interface on port `6666`;
* loads an ELF program onto the target;
* writes fuzz input bytes into target RAM;
* resets the program counter before each execution;
* resumes target execution;
* reads a numeric measurement from `power.txt`;
* treats an input as interesting when it produces a value higher than the previous best value;
* creates a `solutions/` directory and configures it as the LibAFL solutions corpus.

The current corpus does not yet contain a seed input. Therefore, the fuzzing loop cannot perform useful iterations until an initial input is added.

The current implementation also uses `NopMutator`, so even after a seed input is added, inputs will not yet be modified.

## Project Files

The main code is inside the `src` folder.

* `main.rs` contains the LibAFL setup, numeric feedback, measurement logic and fuzzing loop.
* `openocd.rs` contains the functions used to communicate with OpenOCD.

The repository also contains:

* `Cargo.toml` and `Cargo.lock` for the Rust dependencies;
* `solutions/`, which is created automatically when the program runs and is configured as the LibAFL solutions corpus;
* `RUNNING.md` with the setup and execution steps;
* `TODO.md` with the remaining work.

The current numeric feedback is used as normal corpus feedback. Therefore, inputs that produce a new best measurement are treated as interesting and added to the in-memory corpus. They are not currently written to the `solutions/` directory.

## How the Current Version Works

When the program starts, it connects to OpenOCD at:

`127.0.0.1:6666`

It then loads the target program from:

`testcases/program.elf`

The current code uses:

* `0x80000000` as the program start address;
* `0x80010000` as the RAM address for the fuzz input.

Before the fuzzing loop starts, the program:

1. resets and initializes the target;
2. loads the ELF program;
3. sets the program counter to `0x80000000`;
4. reads an idle measurement from `power.txt`;
5. resumes the target;
6. waits for 100 milliseconds;
7. reads a running measurement from `power.txt`.

Once a seed input is available, each fuzzing iteration is intended to:

1. save the current input as `current_input.bin`;
2. reset and initialize the target through OpenOCD;
3. write the input into target RAM;
4. set the program counter;
5. resume the target;
6. wait for 100 milliseconds;
7. after the target execution finishes, the numeric feedback reads the latest value from `power.txt`.

If the new measurement is higher than the previous best value, the input is treated as interesting and added to the in-memory corpus.

## Current Limitations

The current version is not yet a complete end-to-end setup.

The main limitations are:

* the power value is read from `power.txt` instead of directly from the measurement device;
* the correct OpenOCD interface and target configuration still need to be selected;
* the hardware addresses still need to be confirmed on the final target;
* the target program must be modified or confirmed to read input from `0x80010000`;
* the fuzzer currently uses `NopMutator`, so it does not generate modified inputs;
* the input corpus starts empty;
* interesting inputs are not currently persisted to the `solutions/` directory;
* OpenOCD textual error responses are not currently checked;
* the full setup has not been tested on the final hardware.

The remaining work is listed in `TODO.md`.

The setup and run instructions are provided in `RUNNING.md`.
