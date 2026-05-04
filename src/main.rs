extern crate libafl;
extern crate libafl_bolts;

use std::io::{Read, Write};
use std::net::TcpStream;

use std::{
    borrow::Cow,
    fs::{read_to_string, write},
    num::NonZeroUsize,
    path::PathBuf,
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
}

impl NumericFeedback {
    fn new() -> Self {
        Self { best: f64::MIN }
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
        let value = numeric_measurement();

        if value > self.best {
            self.best = value;
            println!("New best value: {}", value);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Temporary fake measurement.
///Will later read real power data from oscilloscope / USBTMC / VISA.
fn numeric_measurement() -> f64 {
    measurement_from_file()
    // later: measurement_from_oscilloscope()
}

fn measurement_from_file() -> f64 {
    match read_to_string("power.txt") {
        Ok(s) => s.trim().parse::<f64>().unwrap_or(0.0),
        Err(_) => 0.0,
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
        self.send_command("reset init")?;
        self.send_command(&format!("load_image {}", binary_path))?;
        self.send_command(&format!("verify_image {} 0x0 elf", binary_path))?;
        self.send_command("halt 1000")?;
        self.send_command("set_reg {pc 0x80000000}")?;
        self.send_command("halt 1000")?;
        Ok(())
    }

    fn resume(&mut self) -> std::io::Result<()> {
        self.send_command("resume")?;
        Ok(())
    }
}

/// Executor target: apply the input.
/// For now, write input to a file to prove execution happens.
fn target(input: &BytesInput) -> ExitKind {
    let _ = write("current_input.bin", input.target_bytes().as_slice());
    ExitKind::Ok
}

fn main() -> Result<(), Error> {
    let binary_path = "testcases/program.elf";

    let mut openocd = OpenOcd::connect("127.0.0.1:6666").expect("Could not connect to OpenOCD");

    openocd
        .load_program(binary_path)
        .expect("Failed to load program");

    let idle_power = numeric_measurement();
    println!("Idle power: {}", idle_power);

    openocd.resume().expect("Failed to resume");

    let running_power = numeric_measurement();
    println!("Running power: {}", running_power);

    let rand = StdRand::with_seed(current_nanos());

    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::new(PathBuf::from("solutions"))?;

    let mut feedback = NumericFeedback::new();
    let mut objective = ();

    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = NopMonitor::new();
    let mut manager = SimpleEventManager::new(monitor);

    let mut executor =
        InProcessExecutor::new(target, tuple_list!(), &mut fuzzer, &mut state, &mut manager)?;

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
