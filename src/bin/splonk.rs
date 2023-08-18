use std::ffi::{OsStr, OsString};
use std::mem::{self, size_of, size_of_val};
use std::os::windows::prelude::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr::{self, addr_of_mut};
use std::slice::{self, from_raw_parts};

use color_eyre::eyre::{eyre, Context, Result};
use magixui::{
    contains_wide, create_command_line_widestring, enable_privilege, Process,
    ProcessFlowInstruction, ProcessSnapshot, ProcessToken, SIDError, TokenInformation,
    WrappedHandle, WrappedImpersonation, WrappedSID,
};
use thiserror::Error;
use windows::core::PWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_PRIVILEGE_NOT_HELD, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Security::{
    DuplicateTokenEx, EqualSid, LookupAccountNameW, SecurityImpersonation, TokenPrimary,
    SECURITY_ATTRIBUTES, SE_ASSIGNPRIMARYTOKEN_NAME, SE_DEBUG_NAME, SE_INCREASE_QUOTA_NAME,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_QUERY_SOURCE, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Environment::CreateEnvironmentBlock;
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSFreeMemory, WTSGetActiveConsoleSessionId,
};
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
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
            }
            (Some(_), ..) => Err(OperationModeBuilderError::ArgumentUnexpected(argument))?,
        };

        Ok(())
    }

    fn push_processbuilder(&mut self, argument: OsString) -> Result<(), OperationModeBuilderError> {
        let Self::ProcessBuilder { process_name } = self else { unreachable!("Developer OOPSIE") };
        match (&process_name,) {
            (None, ..) => mem::replace(process_name, Some(argument)),
            (Some(_), ..) => Err(OperationModeBuilderError::ArgumentUnexpected(argument))?,
        };

        Ok(())
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
                    match launch_process(arguments, access_token)
                        .wrap_err("During child process setup")?
                    {
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
    desired_access: u32,
) -> Option<WrappedHandle<ProcessToken>> {
    process_handle
        .new_token(desired_access)
        .or_else(|_| process_handle.new_token(desired_access & !TOKEN_QUERY_SOURCE.0))
        .ok()
}

fn match_process_basename(path: &Path, needle: &OsString) -> bool {
    let needle: Vec<_> = needle.encode_wide().collect();
    path.file_stem()
        .map(|stem| stem.encode_wide().collect::<Vec<_>>())
        .map(|haystack| contains_wide(&haystack, &needle))
        .is_some_and(|result| result == true)
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

        // WARN; Specific mask required for all the operations further down the execution path!
        // TOKEN_ASSIGN_PRIMARY => Use the token to start a new process
        // ..
        let desired_access =
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY;
        let process_token = match get_process_token(&process_handle, desired_access.0) {
            None => continue,
            Some(token) => token,
        };

        let user_info = TokenInformation::<TOKEN_USER>::new(&process_token)?;

        let process_match = match args.mode {
            OperationMode::User { ref user_sid } => *user_sid == user_info.as_ref().User.Sid,
            OperationMode::Process { ref process_name } => {
                let process_path = process_handle.get_process_image_path()?;
                match_process_basename(&process_path, process_name)
            }
        };

        if !process_match {
            continue;
        }

        if let Some(process_name_filter) = args.process_name_filter.as_ref() {
            let haystack = OsString::from_wide(&process.szExeFile);
            let haystack = Path::new(&haystack);
            let is_match = match_process_basename(&haystack, process_name_filter);
            if is_match == false {
                continue;
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

fn launch_process(
    args: Arguments,
    target_access_token: WrappedHandle<ProcessToken>,
) -> Result<ProcessFlowInstruction<()>> {
    let mut process_security_attributes = SECURITY_ATTRIBUTES::default();
    process_security_attributes.nLength = size_of_val(&process_security_attributes) as _;
    process_security_attributes.bInheritHandle = true.into();
    process_security_attributes.lpSecurityDescriptor = ptr::null_mut();

    let mut startup_info = STARTUPINFOW::default();
    startup_info.cb = size_of_val(&startup_info) as _;

    let mut command_line = match create_command_line_widestring(&args.command_line) {
        Some(command_line) => command_line,
        None => {
            return Err(eyre!("No command provided"));
        }
    };

    println!(
        "Command line: {:?}",
        char::decode_utf16(command_line.clone())
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
    );

    // TODO; Cannot inherit handles accross sessions
    process_security_attributes.bInheritHandle = false.into();

    let environment = None;
    let current_directory = None;

    println!("Child setup completed!");

    let impersonation = WrappedImpersonation::impersonate_self(SecurityImpersonation.0)?;

    let current_thread = WrappedHandle::new_from_current_thread()?;
    let thread_token =
        current_thread.new_token((TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY).0, false)?;
    unsafe {
        enable_privilege(&thread_token, SE_INCREASE_QUOTA_NAME)?;
        enable_privilege(&thread_token, SE_ASSIGNPRIMARYTOKEN_NAME)?;
    }

    // ERROR; We cannot discretely check if the target access token has the access right "TOKEN_ASSIGN_PRIMARY"! This is NOT the same as token privileges!
    // Options are to open the token with desires access mask, or performing an operation on the token that requires the specific right and _guess_ a specific right is missing.
    // The token filter providing us our target access token must include TOKEN_ASSIGN_PRIMARY!

    let mut process_info = PROCESS_INFORMATION::default();
    unsafe {
        match CreateProcessAsUserW(
            *target_access_token.get(),
            None,
            PWSTR::from_raw(command_line.as_mut_ptr()),
            Some(&process_security_attributes),
            Some(&process_security_attributes),
            (startup_info.dwFlags & STARTF_USESTDHANDLES) == STARTF_USESTDHANDLES,
            PROCESS_CREATION_FLAGS(0),
            environment,
            current_directory,
            &mut startup_info,
            &mut process_info,
        )
        .ok()
        {
            Ok(_) => { /* OK */ }
            Err(error) => match WIN32_ERROR::from_error(&error) {
                Some(ERROR_PRIVILEGE_NOT_HELD) => {
                    return Err(error).wrap_err("Hit the ERROR_PRIVILEGE_NOT_HELD")?;
                }
                _ => return Err(error).wrap_err("During child process execution")?,
            },
        };
    };

    impersonation.revert()?;
    println!("Started the process successfully!");

    if let Some(wait_millis) = args.wait_for_child {
        println!("Waiting for child process to exit");
        unsafe {
            match WaitForSingleObject(process_info.hProcess, wait_millis) {
                WAIT_OBJECT_0 => {
                    println!("Child process has exited!");
                }
                WAIT_TIMEOUT => {
                    println!("Timeout waiting for child process to exit!");
                }
                e => e.ok()?, // Actual error
            }
        }
    }

    let handles_to_close = [
        process_info.hProcess,
        process_info.hThread,
        startup_info.hStdInput,
        startup_info.hStdOutput,
        startup_info.hStdError,
    ];
    // WARN; Handles might be aliased!
    let mut closed = Vec::with_capacity(handles_to_close.len());
    unsafe {
        for handle in handles_to_close.into_iter() {
            if closed.contains(&handle) {
                continue;
            }

            CloseHandle(handle);
            closed.push(handle);
        }
    }

    println!("Finished!");

    Ok(ProcessFlowInstruction::Terminate)
}

#[cfg(test)]
mod test {
    use std::{ffi::OsString, str::FromStr};

    use magixui::ProcessFlowInstruction;

    use crate::{build_target_access_token, launch_process, Arguments, OperationModeBuilder};

    #[test]
    fn test_user() {
        let command_line: Vec<OsString> =
            vec!["C:\\WINDOWS\\system32\\cmd.exe".into(), "/C".into(), "whoami".into()];
        let mut builder = OperationModeBuilder::new();
        builder.push("user".into()).unwrap();
        builder.push("bert".into()).unwrap();

        let mut arguments = Arguments {
            mode: builder.build().unwrap(),
            wait_for_child: None,
            process_name_filter: None,
            command_line,
        };

        let ProcessFlowInstruction::Continue(access_token) =
            build_target_access_token(&mut arguments).unwrap()
        else {
            unreachable!()
        };
        launch_process(arguments, access_token).unwrap();
    }
}
