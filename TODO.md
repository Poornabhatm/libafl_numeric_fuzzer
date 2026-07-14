# Remaining Work

The current version is a prototype. The following parts still need to be completed or tested on the final hardware.

## Add an Initial Input

The current corpus starts empty, so the fuzzer does not yet have an input to work with.

A seed input should be added before starting the fuzzing loop. This could be loaded from a file or created directly in the code.

## Replace the Current Mutator

The code currently uses `NopMutator`, which does not change the input.

This should later be replaced with a LibAFL mutator or a custom mutator that matches the expected input format.

## Complete the Power Measurement

The current version reads the measurement from `power.txt`.

The original goal was to read the value directly from the power measurement device. This still needs to be implemented using a suitable VISA library.

The remaining work includes:

- selecting a working VISA implementation;
- connecting to the measurement device;
- sending the correct measurement command;
- reading and converting the returned value;
- handling connection and measurement errors.

## Confirm the OpenOCD Configuration

The correct OpenOCD interface and target configuration files still need to be identified for the final hardware.

The setup should be tested with the actual debug adapter and RISC-V target.

## Verify the Target Addresses

The current code uses:

- `0x80000000` as the program start address;
- `0x80010000` as the RAM address for the fuzz input.

These addresses must be checked against the memory map of the final target.

The target program must also be updated or verified so that it reads the fuzz input from `0x80010000`.

## Improve OpenOCD Error Handling

The current implementation only checks whether the TCP communication succeeded.

OpenOCD can still return an error message even when the TCP connection works. The returned command response should be checked and reported properly.

It would also be useful to add read and write timeouts so that the program does not wait indefinitely if OpenOCD stops responding.

## Improve Input Transfer Speed

The current code writes the fuzz input into RAM one byte at a time using the OpenOCD `mwb` command.

This is simple, but it can be slow for larger inputs. A bulk memory-write method should be investigated later.

## Define the Final Measurement Method

The current feedback uses the latest value from `power.txt`.

The final setup should clearly define whether the fuzzer should maximize:

- absolute running power;
- running power minus idle power;
- peak power;
- average power over several samples.

## Save Interesting Inputs to Disk

The program creates a `solutions/` directory, but inputs that produce a new best measurement are currently added only to the in-memory corpus.

The LibAFL feedback and objective setup should be changed so that new best-measurement inputs are saved to disk. The saved files should also include enough information to identify the corresponding measurement value.

## Complete End-to-End Testing

The full setup still needs to be tested on the actual hardware.

This includes:

1. starting OpenOCD;
2. connecting from the Rust program;
3. loading the ELF file;
4. writing the fuzz input into RAM;
5. running the target;
6. reading the power measurement;
7. verifying that an input producing a new best value is saved correctly after disk persistence has been implemented.

## Make Configuration Easier

The following values are currently hardcoded in `main.rs`:

- OpenOCD address;
- ELF file path;
- program start address;
- input RAM address;
- measurement file path;
- execution delay.

These should later be moved to command-line arguments or a configuration file.


