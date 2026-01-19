// External measurement is currently file-based (power.txt)
// and will later be replaced by OpenOCD TCP communication.

extern crate libafl;
extern crate libafl_bolts;

use std::{
    num::NonZeroUsize,
    path::PathBuf,
    borrow::Cow,
    fs::{read_to_string, write},
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
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::tuple_list,
    AsSlice,
};
use libafl::Error;
use libafl_bolts::Named;

#[derive(Clone, Debug)]
struct NumericFeedback {
    best: f64,
}

impl NumericFeedback {
    fn new() -> Self {
        Self { best: f64::MIN }
    }
}

static NUMERIC_FEEDBACK_NAME: Cow<'static, str> =
    Cow::Borrowed("NumericFeedback");

impl Named for NumericFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &NUMERIC_FEEDBACK_NAME
    }
}

impl<C, I, R, SC> StateInitializer<StdState<C, I, R, SC>>
    for NumericFeedback
{
    fn init_state(
        &mut self,
        _state: &mut StdState<C, I, R, SC>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, OT>
    Feedback<
        EM,
        BytesInput,
        OT,
        StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            OnDiskCorpus<BytesInput>,
        >,
    > for NumericFeedback
where
    OT: ObserversTuple<
        BytesInput,
        StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            OnDiskCorpus<BytesInput>,
        >,
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
/// Will later read real power data from FPGA / OpenOCD.
fn numeric_measurement() -> f64 {
        match read_to_string("power.txt") {
        Ok(s) => s.trim().parse::<f64>().unwrap_or(0.0),
        Err(e) => 0.0
        }
    }


/// Executor target: apply the input.
/// For now, write input to a file to prove execution happens.
fn target(input: &BytesInput) -> ExitKind {
    let _ = write("current_input.bin", input.target_bytes().as_slice());
    ExitKind::Ok
}

fn main() -> Result<(), Error> {
    let rand = StdRand::with_seed(current_nanos());

    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::new(PathBuf::from("solutions"))?;

    let mut feedback = NumericFeedback::new();
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

    let mut executor = InProcessExecutor::new(
        target,
        tuple_list!(),
        &mut fuzzer,
        &mut state,
        &mut manager,
    )?;

    let mutator = NopMutator::new(MutationResult::Skipped);
    let stage = StdMutationalStage::new(mutator);

    let mut generator =
        RandPrintablesGenerator::new(NonZeroUsize::new(32).unwrap());

    state.generate_initial_inputs(
        &mut fuzzer,
        &mut executor,
        &mut generator,
        &mut manager,
        8,
    )?;

    fuzzer.fuzz_loop(
        &mut tuple_list!(stage),
        &mut executor,
        &mut state,
        &mut manager,
    )?;

    Ok(())
}
