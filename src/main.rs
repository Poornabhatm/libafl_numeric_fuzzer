mod openocd;

use std::{
    borrow::Cow,
    fs::{read_to_string, write},
    path::PathBuf,
    thread,
    time::Duration,
};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::{Feedback, StateInitializer},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::NopMonitor,
    mutators::{MutationResult, NopMutator},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    Error,
};

use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::tuple_list,
    AsSlice,
    Named,
};

use openocd::OpenOcd;

trait Measurement {
    fn measure(&mut self) -> f64;
}

#[derive(Clone, Debug)]
struct FileMeasurement {
    path: String,
}

impl FileMeasurement {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

impl Measurement for FileMeasurement {
    fn measure(&mut self) -> f64 {
        match read_to_string(&self.path) {
            Ok(s) => s.trim().parse::<f64>().unwrap_or(0.0),
            Err(_) => 0.0,
        }
    }
}

#[derive(Clone, Debug)]
struct NumericFeedback {
    best: f64,
    measurement: FileMeasurement,
    name: Cow<'static, str>,
}

impl NumericFeedback {
    fn new(measurement: FileMeasurement) -> Self {
        Self {
            best: f64::MIN,
            measurement,
            name: Cow::Borrowed("NumericFeedback"),
        }
    }
}

impl Named for NumericFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for NumericFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for NumericFeedback {
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let value = self.measurement.measure();

        if value > self.best {
            self.best = value;
            println!("New best measurement: {}", value);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn main() -> Result<(), Error> {
    std::fs::create_dir_all("solutions").expect("Failed to create solutions directory");

    let binary_path = "testcases/program.elf";

    let program_start_addr: u32 = 0x80000000;

    // Assumed RAM address where fuzz input will be written.
    // This must be a valid writable RAM address on the real target.
    // The target program must read from this same address.
    let input_addr: u32 = 0x80010000;

    // Connect to OpenOCD only once.
    let mut openocd =
        OpenOcd::connect("127.0.0.1:6666").expect("Could not connect to OpenOCD");

    // Load ELF program using OpenOCD `load`.
    openocd
        .load_program(binary_path, program_start_addr)
        .expect("Failed to load program");

    // Measure idle power before running.
    let mut idle_measurement = FileMeasurement::new("power.txt");
    let idle_power = idle_measurement.measure();
    println!("Idle power: {}", idle_power);

    // Resume once to get running measurement.
    openocd.resume().expect("Failed to resume target");

    thread::sleep(Duration::from_millis(100));

    let mut running_measurement = FileMeasurement::new("power.txt");
    let running_power = running_measurement.measure();
    println!("Running power: {}", running_power);

    let rand = StdRand::with_seed(current_nanos());

    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::new(PathBuf::from("solutions"))?;

    let measurement = FileMeasurement::new("power.txt");
    let mut feedback = NumericFeedback::new(measurement);

    let mut objective = ();

    let mut state = StdState::new(
        rand,
        corpus,
        solutions,
        &mut feedback,
        &mut objective,
    )?;

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = NopMonitor::new();
    let mut manager = SimpleEventManager::new(monitor);

    let mut target = |input: &BytesInput| -> ExitKind {
        let bytes = input.target_bytes();
        let data = bytes.as_slice();

        // Save current fuzz input locally for debugging.
        if let Err(e) = write("current_input.bin", data) {
            eprintln!("Failed to write current_input.bin: {}", e);
            return ExitKind::Crash;
        }

        if let Err(e) = openocd.reset_init() {
            eprintln!("OpenOCD reset init failed: {}", e);
            return ExitKind::Crash;
        }

        // Write fuzz input into target RAM.
        if let Err(e) = openocd.write_input_to_ram(input_addr, data) {
            eprintln!("Writing fuzz input to target RAM failed: {}", e);
            return ExitKind::Crash;
        }

        // Reset program counter to program start.
        if let Err(e) = openocd.set_pc(program_start_addr) {
            eprintln!("Setting PC failed: {}", e);
            return ExitKind::Crash;
        }

        // Resume target execution.
        if let Err(e) = openocd.resume() {
            eprintln!("OpenOCD resume failed: {}", e);
            return ExitKind::Crash;
        }

        // Give the target some time to execute before measurement happens.
        thread::sleep(Duration::from_millis(100));

        ExitKind::Ok
    };

    let mut executor = InProcessExecutor::new(
        &mut target,
        tuple_list!(),
        &mut fuzzer,
        &mut state,
        &mut manager,
    )?;

    let mutator = NopMutator::new(MutationResult::Skipped);
    let stage = StdMutationalStage::new(mutator);
    let mut stages = tuple_list!(stage);

fuzzer.fuzz_loop(
    &mut stages,
    &mut executor,
    &mut state,
    &mut manager,
)?;

    Ok(())
}