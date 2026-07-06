extern crate libafl;
extern crate libafl_bolts;

use std::io::{Read, Write};
use std::net::TcpStream;

use std::{
    borrow::Cow,
    fs::{read_to_string, write},
    num::NonZeroUsize,
    path::PathBuf,
    thread,
    time::Duration,
};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{Feedback, StateInitializer},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{MutationResult, NopMutator},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

use libafl::monitors::NopMonitor;
use libafl::observers::ObserversTuple;
use libafl::Error;
use libafl_bolts::Named;
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};

#[derive(Clone, Debug)]
struct NumericFeedback {
    best: f64,
    measurement: FileMeasurement,
}

impl NumericFeedback {
    fn new(measurement: FileMeasurement) -> Self {
        Self {
            best: f64::MIN,
            measurement,
        }
    }
}

static NUMERIC_FEEDBACK_NAME: Cow<'static, str> = Cow::Borrowed("NumericFeedback");

impl Named for NumericFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &NUMERIC_FEEDBACK_NAME
    }
}

impl<C, I, R, SC> StateInitializer<StdState<C, I, R, SC>> for NumericFeedback {
    fn init_state(&mut self, _state: &mut StdState<C, I, R, SC>) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, OT>
    Feedback<
        EM,
        BytesInput,
        OT,
        StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>,
    > for NumericFeedback
where
    OT: ObserversTuple<
        BytesInput,
        StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>,
    >,
{
    fn is_interesting(
        &mut self,
        _state: &mut StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            OnDiskCorpus<BytesInput>,
        >,
        _manager: &mut EM,
        _input: &BytesInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let value = self.measurement.measure();

        if value > self.best {
            self.best = value;
            println!("New best value: {}", value);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

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

struct OpenOcd {
    stream: TcpStream,
}

impl OpenOcd {
    const TOKEN: u8 = 0x1a;

     fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        println!("Connected to OpenOCD!");
        Ok(Self { stream })
    }

     fn send_command(&mut self, command: &str) -> std::io::Result<String> {
        let full_command = format!("{}\x1a", command);
        self.stream.write_all(full_command.as_bytes())?;

        let mut response = Vec::new();
        let mut buf = [0u8; 256];

        loop {
            let n = self.stream.read(&mut buf)?;

            if n == 0 {
                break;
            }

            response.extend_from_slice(&buf[..n]);

            if response.contains(&Self::TOKEN) {
                break;
            }
        }

        if let Some(pos) = response.iter().position(|&b| b == Self::TOKEN) {
            response.truncate(pos);
        }

        Ok(String::from_utf8_lossy(&response).to_string())
    }

     fn load_program(&mut self, binary_path: &str) -> std::io::Result<()> {
        println!("Loading program: {}", binary_path);

        self.send_command("reset init")?;
        self.send_command(&format!("load_image {}", binary_path))?;
        self.send_command(&format!("verify_image {} 0x0 elf", binary_path))?;
        self.send_command("halt 1000")?;
        self.send_command("set_reg {pc 0x80000000}")?;
        self.send_command("halt 1000")?;

        println!("Program loaded successfully.");
        Ok(())
    }

     fn halt(&mut self) -> std::io::Result<()> {
        self.send_command("halt 1000")?;
        Ok(())
    }

     fn resume(&mut self) -> std::io::Result<()> {
        self.send_command("resume")?;
        Ok(())
    }

     fn set_pc(&mut self, pc: u32) -> std::io::Result<()> {
        self.send_command(&format!("set_reg {{pc 0x{:08x}}}", pc))?;
        Ok(())
    }

     fn write_input_to_ram(&mut self, addr: u32, data: &[u8]) -> std::io::Result<()> {
        for (i, byte) in data.iter().enumerate() {
            let target_addr = addr + i as u32;
            self.send_command(&format!("mwb 0x{:08x} 0x{:02x}", target_addr, byte))?;
        }

        Ok(())
    }
}

fn main() -> Result<(), Error> {
    std::fs::create_dir_all("solutions").expect("Failed to create solutions directory");

    let binary_path = "testcases/program.elf";

    // Assumed start address of the program.
    let program_start_addr: u32 = 0x80000000;

    // Assumed RAM address where fuzz input will be written.
    // This must be a valid writable RAM address on the real target.
    // The target program must also read from this same address.
    let input_addr: u32 = 0x80010000;

    let mut openocd =
        OpenOcd::connect("127.0.0.1:6666").expect("Could not connect to OpenOCD");

    openocd
        .load_program(binary_path)
        .expect("Failed to load program");

    let mut idle_measurement = FileMeasurement::new("power.txt");
    let idle_power = idle_measurement.measure();
    println!("Idle power: {}", idle_power);

    let rand = StdRand::with_seed(current_nanos());

    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::new(PathBuf::from("solutions"))?;

    let measurement = FileMeasurement::new("power.txt");
    let mut feedback = NumericFeedback::new(measurement);
    let mut objective = ();

    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

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

        // Halt the target before modifying memory.
        if let Err(e) = openocd.halt() {
            eprintln!("OpenOCD halt failed: {}", e);
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
        // Later this delay may need to be adjusted based on the oscilloscope timing.
        thread::sleep(Duration::from_millis(100));

        ExitKind::Ok
    };

    let mut executor =
        InProcessExecutor::new(&mut target, tuple_list!(), &mut fuzzer, &mut state, &mut manager)?;

    let mutator = NopMutator::new(MutationResult::Skipped);
    let stage = StdMutationalStage::new(mutator);

    let mut generator = RandPrintablesGenerator::new(NonZeroUsize::new(32).unwrap());

    state.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut manager, 8)?;

    fuzzer.fuzz_loop(
        &mut tuple_list!(stage),
        &mut executor,
        &mut state,
        &mut manager,
    )?;

    Ok(())
}