use std::ffi::{OsStr, OsString};
use std::hint::black_box;
use std::mem::{self, size_of, size_of_val};
use std::ops::Shl;
use std::os::windows::prelude::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr::{self, addr_of_mut};
use std::slice::{self, from_raw_parts};
use std::thread::current;

use color_eyre::eyre::{eyre, Context, Result};
use lexopt::Arg;
use magixui::{
    contains_wide, create_command_line_widestring, enable_privilege, Process,
    ProcessFlowInstruction, ProcessSnapshot, ProcessToken, SIDError, TokenInformation,
    WrappedHandle, WrappedImpersonation, WrappedSID,
};
use thiserror::Error;
use windows::core::{w, Error, HRESULT, PWSTR};
use windows::Wdk::Foundation::{NtQueryObject, ObjectTypeInformation};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_INSUFFICIENT_BUFFER,
    ERROR_PRIVILEGE_NOT_HELD, HANDLE, STATUS_INFO_LENGTH_MISMATCH, STATUS_NO_MEMORY,
    STATUS_SUCCESS, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Security::{
    DuplicateTokenEx, EqualSid, ImpersonateSelf, LookupAccountNameW, SecurityImpersonation,
    TokenPrimary, SECURITY_ATTRIBUTES, SE_ASSIGNPRIMARYTOKEN_NAME, SE_DEBUG_NAME,
    SE_INCREASE_QUOTA_NAME, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_QUERY_SOURCE, TOKEN_USER,
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
    CreateProcessAsUserW, GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW,
    WaitForSingleObject, PROCESS_CREATION_FLAGS, PROCESS_DUP_HANDLE, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOW,
};
use windows::Win32::System::WindowsProgramming::{
    PUBLIC_OBJECT_TYPE_INFORMATION, SYSTEM_BASIC_INFORMATION,
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

#[repr(C)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub ProcessId: u16,
    pub CreatorBackTraceIndex: u16,
    pub ObjectTypeIndex: u8,
    pub HandleAttributes: u8,
    pub HandleValue: u16,
    pub Object: *mut std::ffi::c_void,
    pub GrantedAccess: u32,
}

impl ::core::marker::Copy for SYSTEM_HANDLE_TABLE_ENTRY_INFO {}
impl ::core::clone::Clone for SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    fn clone(&self) -> Self {
        *self
    }
}

impl ::core::fmt::Debug for SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("SYSTEM_HANDLE_TABLE_ENTRY_INFO")
            .field("ProcessId", &self.ProcessId)
            .field("CreatorBackTraceIndex", &self.CreatorBackTraceIndex)
            .field("ObjectTypeIndex", &self.ObjectTypeIndex)
            .field("HandleAttributes", &self.HandleAttributes)
            .field("HandleValue", &self.HandleValue)
            .field("Object", &self.Object)
            .field("GrantedAccess", &self.GrantedAccess)
            .finish()
    }
}

impl windows::core::TypeKind for SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    type TypeKind = windows::core::CopyType;
}

impl ::core::cmp::PartialEq for SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    fn eq(&self, other: &Self) -> bool {
        self.ProcessId == other.ProcessId
            && self.CreatorBackTraceIndex == other.CreatorBackTraceIndex
            && self.ObjectTypeIndex == other.ObjectTypeIndex
            && self.HandleAttributes == other.HandleAttributes
            && self.HandleValue == other.HandleValue
            && self.Object == other.Object
            && self.GrantedAccess == other.GrantedAccess
    }
}

impl ::core::cmp::Eq for SYSTEM_HANDLE_TABLE_ENTRY_INFO {}

impl ::core::default::Default for SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    fn default() -> Self {
        unsafe { ::core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub NumberOfHandles: u32,
    pub Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}

impl ::core::marker::Copy for SYSTEM_HANDLE_INFORMATION {}
impl ::core::clone::Clone for SYSTEM_HANDLE_INFORMATION {
    fn clone(&self) -> Self {
        *self
    }
}

impl ::core::fmt::Debug for SYSTEM_HANDLE_INFORMATION {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("SYSTEM_HANDLE_INFORMATION")
            .field("NumberOfHandles", &self.NumberOfHandles)
            .field("Handles", &self.Handles)
            .finish()
    }
}

impl windows::core::TypeKind for SYSTEM_HANDLE_INFORMATION {
    type TypeKind = windows::core::CopyType;
}

impl ::core::cmp::PartialEq for SYSTEM_HANDLE_INFORMATION {
    fn eq(&self, other: &Self) -> bool {
        self.NumberOfHandles == other.NumberOfHandles && self.Handles == other.Handles
    }
}

impl ::core::cmp::Eq for SYSTEM_HANDLE_INFORMATION {}
impl ::core::default::Default for SYSTEM_HANDLE_INFORMATION {
    fn default() -> Self {
        unsafe { ::core::mem::zeroed() }
    }
}

fn build_target_access_token_ntsystem(
    args: &mut Arguments,
) -> Result<ProcessFlowInstruction<WrappedHandle<ProcessToken>>> {
    let impersonation = WrappedImpersonation::impersonate_self(SecurityImpersonation.0)?;
    let current_thread = WrappedHandle::new_from_current_thread()?;
    let thread_token =
        current_thread.new_token((TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY).0, false)?;

    let system_handle_information = SYSTEM_INFORMATION_CLASS(16);
    let mut required_size = 0x400;
    let mut information_buffer = Vec::<u8>::with_capacity(required_size as _);

    loop {
        unsafe {
            // ERROR; Handle table will change between calls to kernel, so a static approach to buffer size
            // is not optimal.
            match NtQuerySystemInformation(
                system_handle_information,
                information_buffer.as_mut_ptr().cast(),
                required_size.clone(),
                &mut required_size,
            ) {
                Ok(_) => break,
                Err(error) if error.code() == STATUS_INFO_LENGTH_MISMATCH.to_hresult() => {
                    required_size = required_size
                        .checked_shl(1)
                        .expect("Integer overflow at NtQuerySystemInformation");
                    // NOTE; Works because vector length is always 0
                    information_buffer.reserve(required_size as _);
                }
                Err(error) => Err(error)?,
            }
        };
    }

    let header_handles_information =
        unsafe { &*(information_buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION) };
    assert_eq!(
        required_size as usize,
        (size_of::<SYSTEM_HANDLE_INFORMATION>() - size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>()
            + (header_handles_information.NumberOfHandles as usize
                * size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())),
        "Type definition mismatch at SYSTEM_HANDLE_TABLE_ENTRY_INFO!"
    );

    let handles = unsafe {
        slice::from_raw_parts(
            header_handles_information.Handles.as_ptr(),
            header_handles_information.NumberOfHandles as _,
        )
    };

    for handle_info in handles {
        eprintln!("Attempt opening process {0}", handle_info.ProcessId);
        // If we can open the process owning the handle, we can open the handle.
        let process = unsafe {
            match OpenProcess(PROCESS_DUP_HANDLE, false, handle_info.ProcessId as _) {
                Ok(handle) => WrappedHandle::new(handle),
                Err(_) => continue,
            }
        };

        eprintln!("Attempt copying token");
        // Copy handle into our own process domain
        let target_handle = unsafe {
            let mut handle = HANDLE::default();
            match DuplicateHandle(
                *process.get(),
                HANDLE(handle_info.HandleValue as _),
                GetCurrentProcess(),
                &mut handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            ) {
                Ok(_) => { /* Do nothing */ }
                Err(_) => continue,
            };
            WrappedHandle::<ProcessToken>::new(handle)
        };

        // Filter handle for desired usecase
        let mut required_size = 0;
        unsafe {
            match NtQueryObject(
                *target_handle.get(),
                ObjectTypeInformation,
                None,
                0,
                Some(&mut required_size),
            ) {
                Ok(_) => unreachable!("This API call is setup to fail!"),
                Err(error) if error.code() == STATUS_INFO_LENGTH_MISMATCH.to_hresult() => {
                    /* Expected error */
                }
                Err(error) => Err(error)?,
            }
        };

        let mut handle_type_buffer = Vec::<u8>::with_capacity(required_size as usize);
        unsafe {
            NtQueryObject(
                *target_handle.get(),
                ObjectTypeInformation,
                Some(handle_type_buffer.as_mut_ptr().cast()),
                required_size.clone(),
                Some(&mut required_size),
            )
            .wrap_err("While retrieving token type information")?
        };
        let header_handle_type =
            unsafe { &*(handle_type_buffer.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION) };
        if header_handle_type.TypeName.Length == 0 || header_handle_type.TypeName.Buffer.0.is_null()
        {
            continue;
        }

        let type_nameslice = unsafe {
            slice::from_raw_parts(
                header_handle_type.TypeName.Buffer.0,
                // WARN; Length is expressed in BYTES!
                // WARN; Length is expressed WITHOUT null-terminator
                header_handle_type
                    .TypeName
                    .Length
                    .checked_div(2)
                    .expect("Integer Underflow at TOKEN_TYPENAME") as _,
            )
        };
        // NOTE; encode_utf16 doesn't add a null-terminator
        let token_type_string: Vec<_> = "Token".encode_utf16().collect();
        println!("{0}", handle_info.ProcessId);
        println!("{:02X?}", &token_type_string);
        println!("{:02X?}", type_nameslice);
        if type_nameslice != &token_type_string {
            continue;
        }

        struct TokenDetails {
            Handle: WrappedHandle,
            Username: OsStr,
        }

        TokenInformation::<TOKEN_USER>::new(&target_handle)?;

        todo!("Parse handle as an ACCESS TOKEN and do stuffs");
    }

    unimplemented!()
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
        ) {
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
                e => Err(eyre!(
                    "Unexpected error {0:?} while waiting for child process to exit",
                    e.0
                ))?,
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

            let _ = CloseHandle(handle);
            closed.push(handle);
        }
    }

    println!("Finished!");

    Ok(ProcessFlowInstruction::Terminate)
}

#[cfg(test)]
mod test {
    use std::{ffi::OsString, str::FromStr};

    use color_eyre::eyre::{eyre, Context, Result};
    use magixui::ProcessFlowInstruction;

    use crate::{
        build_target_access_token, build_target_access_token_ntsystem, launch_process, Arguments,
        OperationModeBuilder,
    };

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

    #[test]
    fn test_ntsystem() -> Result<()> {
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

        match build_target_access_token_ntsystem(&mut arguments) {
            Ok(_) => {}
            Err(error) => Err(error)?,
        };
        Ok(())
    }
}
