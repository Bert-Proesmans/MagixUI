use std::ptr::{self, addr_of_mut};
use std::slice;

use color_eyre::eyre::{eyre, Result, WrapErr};
use magixui::ProcessFlowInstruction;
use windows::Win32::System::RemoteDesktop::{WTSActive, WTSFreeMemory};
use windows::Win32::System::{
    RemoteDesktop::{WTSEnumerateSessionsW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW},
    Threading::INFINITE,
};

macro_rules! HELP {
    () => {
"\
Magix Tada

Launch a child process into a different user logon session, window station, desktop than the parent process is currently using.

USAGE:
    {bin_name} [FLAGS] [OPTIONS] -- ProcessPath ProcessArgument1 ProcessArgument2 ProcessArgumentN

FLAGS:
    --help                          Prints help information and exits
    -w, --wait[=milliseconds]       Wait for the child process to exit before continuing, optionally wait for a provided amount of milliseconds

OPTIONS:
    # None yet

ARGS:
    --                              Argument splitter
    ProcessPath       PATH          The location of the process to execute
    ProcessArgumentN  STRING        Arguments passed to the proces on start
"
    };
}

struct Arguments {}

fn main() -> Result<()> {
    color_eyre::install()?;

    match parse_args().wrap_err("During command line arguments parsing")? {
        ProcessFlowInstruction::Terminate => return Ok(()),
        ProcessFlowInstruction::Continue(mut arguments) => {
            match target_session(&mut arguments).wrap_err("During logon session select")? {
                ProcessFlowInstruction::Terminate => return Ok(()),
                ProcessFlowInstruction::Continue(_) => {
                    match launch_process(arguments).wrap_err("During child process setup")? {
                        _ => Ok(()),
                    }
                }
            }
        }
    }
}

fn parse_args() -> Result<ProcessFlowInstruction<Arguments>, lexopt::Error> {
    use lexopt::prelude::*;
    let mut wait_for_child = None;
    let mut command_line = Vec::new();
    let mut startupinfo_mutators: Vec<u32> = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let bin_name = parser.bin_name().unwrap_or("splonk.exe");
                println!(HELP!(), bin_name = bin_name);
                return Ok(ProcessFlowInstruction::Terminate);
            }
            Short('w') | Long("wait") => {
                wait_for_child = match parser.optional_value() {
                    Some(millis) => Some(millis.parse()?),
                    None => Some(INFINITE),
                };
            }
            // NOTE; Everything after -- should be copied as is.
            // We will reconstruct the commandline string from these parts and pass into StartProcess
            Value(argument) => command_line.push(argument),
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(ProcessFlowInstruction::Continue(Arguments {}))
}

fn target_session(args: &mut Arguments) -> Result<ProcessFlowInstruction<u32>> {
    let user_sessions: &[WTS_SESSION_INFOW];
    let mut sessions_ptr: *mut WTS_SESSION_INFOW = ptr::null_mut();
    unsafe {
        let mut session_count: u32 = 0;
        WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            addr_of_mut!(sessions_ptr),
            addr_of_mut!(session_count),
        )
        .ok()?;
        user_sessions = slice::from_raw_parts(sessions_ptr, session_count as _);
    }

    let active_session_id = user_sessions
        .into_iter()
        .find(|session| session.State == WTSActive)
        .map(|session| session.SessionId)
        .unwrap_or(0);
    unsafe {
        WTSFreeMemory(sessions_ptr as _);
    }

    if active_session_id != 0 {
        return Ok(ProcessFlowInstruction::Continue(active_session_id));
    }

    todo!()
}

fn launch_process(mut args: Arguments) -> Result<ProcessFlowInstruction<()>> {
    todo!()
}
