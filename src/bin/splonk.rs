use std::ffi::{OsStr, OsString};
use std::mem::{self, size_of, size_of_val};
use std::os::windows::prelude::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr::{self, addr_of_mut};
use std::slice::{self, from_raw_parts};

use color_eyre::eyre::{eyre, Context, Result};
use magixui::{
    contains_wide, enable_privilege, Process, ProcessFlowInstruction, ProcessSnapshot,
    ProcessToken, SIDError, TokenInformation, WrappedHandle, WrappedImpersonation, WrappedSID,
};
use thiserror::Error;
use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, PSID, WIN32_ERROR};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    DuplicateTokenEx, EqualSid, LookupAccountNameW, SecurityImpersonation, TokenPrimary,
    SECURITY_ATTRIBUTES, SE_DEBUG_NAME, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_QUERY,
    TOKEN_QUERY_SOURCE, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSFreeMemory, WTSGetActiveConsoleSessionId,
};
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::Win32::System::Threading::{
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::{
    RemoteDesktop::{WTSEnumerateSessionsW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW},
    Threading::INFINITE,
};

macro_rules! HELP {
    () => {
"\
Magix Tada

Launch a child process into a different user logon session->window station->desktop than the parent process is currently using.

USAGE:
    {bin_name} [SWITCHES] [OPTIONS] [| [user UserName] [process ProcessName] ] -- ProcessPath ProcessArgument1 ProcessArgument2 ProcessArgumentN

SWITCHES:
    --help                          Prints help information and exits
    -w, --wait                      Wait for the child process to exit before continuing

OPTIONS:
    -w, --wait=milliseconds         Wait for the child process to exit before continuing, but no longer than the provided amount of milliseconds
    -p, --process=processName       The target session must have a process running which image-name property equals the provided processName

SUBCOMMANDS:
    user                            Find the target desktop by comparing user identifiers
    process                         Find the target desktop by comparing running processes

ARGS:
    [IF user]       UserName            STRING      The username of the user that is owner of the session to target
    [IF process]    ProcessName         STRING      The name of the process that is owned by the session to target
                    --                              Argument splitter
                    ProcessPath         PATH        The location of the process to execute
                    ProcessArgumentN    STRING      Arguments passed to the proces on start
"
    };
}

enum OperationMode {
    User { user_sid: WrappedSID },
    Process { process_name: OsString },
}

enum OperationModeBuilder {
    None,
    UserBuilder { user_sid: Option<WrappedSID> },
    ProcessBuilder { process_name: Option<OsString> },
}

#[derive(Error, Debug)]
enum OperationModeBuilderError {
    #[error("The argument {0:?} is not a recognized command")]
    UnknownCommand(String),

    #[error("No subcommand was provided")]
    NoCommand,

    #[error("Argument {1:?} is missing for subcommand {0:?}")]
    IncompleteCommand(String, String),

    #[error("The argument {0:?} was unexpected in this position, for the given command")]
    ArgumentUnexpected(OsString),

    #[error("No user could be resolved for the username value {0:?}")]
    UnknownUsername(OsString, #[source] ::windows::core::Error),
}

impl OperationModeBuilder {
    pub fn new() -> OperationModeBuilder {
        OperationModeBuilder::None
    }

    pub fn can_consume(&self) -> bool {
        match self {
            Self::UserBuilder { user_sid: user_name } if user_name.is_some() => false,
            Self::ProcessBuilder { process_name } if process_name.is_some() => false,
            _ => true,
        }
    }

    pub fn build(self) -> Result<OperationMode, OperationModeBuilderError> {
        match self {
            OperationModeBuilder::None => Err(OperationModeBuilderError::NoCommand),
            OperationModeBuilder::UserBuilder { user_sid: user_name } => {
                if let Some(user_name) = user_name {
                    Ok(OperationMode::User { user_sid: user_name })
                } else {
                    Err(OperationModeBuilderError::IncompleteCommand(
                        String::from("user"),
                        String::from("user_name"),
                    ))
                }
            }
            OperationModeBuilder::ProcessBuilder { process_name } => {
                if let Some(process_name) = process_name {
                    Ok(OperationMode::Process { process_name })
                } else {
                    Err(OperationModeBuilderError::IncompleteCommand(
                        String::from("process"),
                        String::from("process_name"),
                    ))
                }
            }
        }
    }

    pub fn push(&mut self, argument: OsString) -> Result<(), OperationModeBuilderError> {
        match self {
            Self::None => self.replace_self(argument),
            Self::UserBuilder { .. } => self.push_userbuilder(argument),
            Self::ProcessBuilder { .. } => self.push_processbuilder(argument),
        }
    }

    fn replace_self(&mut self, argument: OsString) -> Result<(), OperationModeBuilderError> {
        if let Self::None = self {
            match argument.to_string_lossy() {
                std::borrow::Cow::Borrowed(str) => match str {
                    "user" => {
                        let _ = mem::replace(self, Self::UserBuilder { user_sid: None });
                        Ok(())
                    }
                    "process" => {
                        let _ = mem::replace(self, Self::ProcessBuilder { process_name: None });
                        Ok(())
                    }
                    _ => Err(OperationModeBuilderError::UnknownCommand(str.to_owned()))?,
                },
                _ => {
                    Err(OperationModeBuilderError::UnknownCommand(String::from("[Decode error]")))?
                }
            }
        } else {
            unreachable!("Programmer OOPSIE");
        }
    }

    fn push_userbuilder(&mut self, argument: OsString) -> Result<(), OperationModeBuilderError> {
        let Self::UserBuilder { user_sid } = self else { unreachable!("Developer OOPSIE") };
        match (&user_sid,) {
            (None, ..) => {
                let resolved_user_sid = unsafe {
                    WrappedSID::new_from_local_account(&argument).map_err(move |err| match err {
                        SIDError::Other(win32_error) => {
                            OperationModeBuilderError::UnknownUsername(argument, win32_error)
                        }
                    })?
                };

                let _ = mem::replace(user_sid, Some(resolved_user_sid));
                Ok(())
            }
            (Some(_), ..) => Err(OperationModeBuilderError::ArgumentUnexpected(argument))?,
        }
    }

    fn push_processbuilder(&mut self, argument: OsString) -> Result<(), OperationModeBuilderError> {
        todo!()
    }
}

struct Arguments {
    wait_for_child: Option<u32>,
    process_name_filter: Option<OsString>,
    mode: OperationMode,
    command_line: Vec<OsString>,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    match parse_args().wrap_err("During command line arguments parsing")? {
        ProcessFlowInstruction::Terminate => return Ok(()),
        ProcessFlowInstruction::Continue(mut arguments) => {
            match build_target_access_token(&mut arguments)
                .wrap_err("During logon session select")?
            {
                ProcessFlowInstruction::Terminate => return Ok(()),
                ProcessFlowInstruction::Continue(access_token) => {
                    match launch_process(arguments).wrap_err("During child process setup")? {
                        _ => Ok(()),
                    }
                }
            }
        }
    }
}

fn parse_args() -> Result<ProcessFlowInstruction<Arguments>> {
    use lexopt::prelude::*;
    let mut wait_for_child = None;
    let mut process_name_filter = None;
    let mut operation_builder = OperationModeBuilder::new();
    let mut command_line = Vec::new();

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
            Short('p') | Long("process") => {
                process_name_filter = Some(
                    parser
                        .optional_value()
                        .ok_or(eyre!("No value provided for option 'process'!"))?,
                );
            }
            Value(argument) if operation_builder.can_consume() => {
                if let Err(error) = operation_builder.push(argument) {
                    match error {
                        OperationModeBuilderError::ArgumentUnexpected(argument) => {
                            Err(lexopt::Arg::Value(argument).unexpected())?
                        }
                        _ => Err(error)?,
                    }
                };
            }
            // NOTE; Everything after -- should be copied as is.
            // We will reconstruct the commandline string from these parts and pass into StartProcess
            Value(argument) => command_line.push(argument),
            _ => Err(arg.unexpected())?,
        }
    }

    Ok(ProcessFlowInstruction::Continue(Arguments {
        wait_for_child,
        process_name_filter,
        command_line,
        mode: operation_builder.build()?,
    }))
}

fn build_target_access_token(
    args: &mut Arguments,
) -> Result<ProcessFlowInstruction<WrappedHandle<ProcessToken>>> {
    let impersonation = WrappedImpersonation::impersonate_self(SecurityImpersonation.0)?;

    let current_thread = WrappedHandle::new_from_current_thread()?;
    let thread_token =
        current_thread.new_token((TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY).0, false)?;
    unsafe {
        enable_privilege(&thread_token, SE_DEBUG_NAME)?;
    }

    let mut target_token = None;
    let process_snapshot = ProcessSnapshot::new()?;
    for process in process_snapshot {
        let process = process?;

        let process_handle = match get_process_handle(process.th32ProcessID) {
            None => continue,
            Some(handle) => handle,
        };

        let process_token = match get_process_token(&process_handle) {
            None => continue,
            Some(token) => token,
        };

        let user_info = TokenInformation::<TOKEN_USER>::new(&process_token)?;

        let process_match = match args.mode {
            OperationMode::User { ref user_sid } => *user_sid == user_info.as_ref().User.Sid,
            OperationMode::Process { ref process_name } => todo!(),
        };

        if !process_match {
            continue;
        }

        if let Some(process_name_filter) = args.process_name_filter.as_ref() {
            let needle: Vec<_> = process_name_filter.encode_wide().collect();
            let haystack = OsString::from_wide(&process.szExeFile);
            let haystack = Path::new(&haystack);
            let needle_found = haystack
                .file_stem()
                .map(|stem| stem.encode_wide().collect::<Vec<_>>())
                .map(|haystack| contains_wide(&haystack, &needle));

            match needle_found {
                None | Some(false) => {
                    continue;
                }
                Some(true) => { /* Do nothing */ }
            }
        }

        target_token = Some(process_token.duplicate_impersonation()?);
        break;
    }

    impersonation.revert()?;
    match target_token {
        Some(token) => Ok(ProcessFlowInstruction::Continue(token)),
        None => Ok(ProcessFlowInstruction::Terminate),
    }
}

fn get_process_handle(process_id: u32) -> Option<WrappedHandle<Process>> {
    WrappedHandle::new_from_external_process(process_id, PROCESS_QUERY_INFORMATION.0)
        .or_else(|_| {
            WrappedHandle::new_from_external_process(
                process_id,
                PROCESS_QUERY_LIMITED_INFORMATION.0,
            )
        })
        .ok()
}

fn get_process_token(
    process_handle: &WrappedHandle<Process>,
) -> Option<WrappedHandle<ProcessToken>> {
    let desired_access = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY;
    process_handle
        .new_token(desired_access.0)
        .or_else(|_| process_handle.new_token((desired_access & !TOKEN_QUERY_SOURCE).0))
        .ok()
}

fn target_session_proc(args: &mut Arguments) -> Result<ProcessFlowInstruction<u32>> {
    let mut process_ids = Vec::<u32>::with_capacity(1024);
    let available_buffer = (process_ids.capacity() * size_of::<u32>())
        .try_into()
        .expect("Integer overflow at EnumProcesses");
    let mut consumed_buffer = 0;

    unsafe {
        EnumProcesses(process_ids.as_mut_ptr(), available_buffer, addr_of_mut!(consumed_buffer))
            .ok()?;
    }

    if available_buffer == consumed_buffer {
        return Err(eyre!("Didn't provide enough buffer space to enumerate all processes on this system. This is a programmer's mistake!"));
    }

    let filled_items = consumed_buffer as usize / size_of::<u32>();
    let process_ids: &[u32] = unsafe { from_raw_parts(process_ids.as_ptr().cast(), filled_items) };

    println!("Process IDs: {:?}", process_ids.iter().take(10).collect::<Vec<_>>());

    for process in process_ids.into_iter() {
        println!("Process {}", process);
        if process == &0 {
            continue;
        }
        // let process_handle = unsafe {
        //     match OpenProcess(PROCESS_QUERY_INFORMATION, false, *process) {
        //         Ok(token) => token,
        //         Err(_) => OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, *process)?,
        //     }
        // };

        // let mut process_token = HANDLE::default();
        // unsafe {
        //     OpenProcessToken(
        //         process_handle,
        //         TOKEN_QUERY
        //             | TOKEN_READ
        //             | TOKEN_IMPERSONATE
        //             | TOKEN_QUERY_SOURCE
        //             | TOKEN_DUPLICATE
        //             | TOKEN_ASSIGN_PRIMARY
        //             | TOKEN_EXECUTE,
        //         addr_of_mut!(process_token),
        //     )
        //     .ok()?
        // };
        let process_token = WrappedHandle::new_from_current_process()?;

        // let groups_info = TokenInformation::<TOKEN_GROUPS>::new(&process_token)?;
        // for group in groups_info.get_groups() {
        //     let sid_string = unsafe {
        //         let mut wide_string = PWSTR::null();
        //         ConvertSidToStringSidW(group.Sid, addr_of_mut!(wide_string)).ok()?;
        //         String::from_utf16_lossy(wide_string.as_wide())
        //     };
        //     println!("{sid_string}");
        // }

        println!();
    }

    todo!()
}

fn target_session_wts(args: &mut Arguments) -> Result<ProcessFlowInstruction<u32>> {
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

    let mut active_session_id = user_sessions
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

    active_session_id = unsafe { WTSGetActiveConsoleSessionId() };
    Ok(ProcessFlowInstruction::Continue(active_session_id))
}

fn launch_process(mut args: Arguments) -> Result<ProcessFlowInstruction<()>> {
    todo!()
}
