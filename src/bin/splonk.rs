use std::mem::{self, size_of, size_of_val};
use std::ptr::{self, addr_of_mut};
use std::slice::{self, from_raw_parts};

use color_eyre::eyre::{eyre, Result, WrapErr};
use magixui::{enable_privilege, ProcessFlowInstruction, TokenInformation, WrappedHandle, WrappedImpersonation};
use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, WIN32_ERROR};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    SE_DEBUG_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS,
    TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE, ImpersonateSelf, SECURITY_IMPERSONATION_LEVEL, SecurityImpersonation,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSFreeMemory, WTSGetActiveConsoleSessionId,
};
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

    target_session_snapshot(&mut Arguments {})?;

    todo!();
    // match parse_args().wrap_err("During command line arguments parsing")? {
    //     ProcessFlowInstruction::Terminate => return Ok(()),
    //     ProcessFlowInstruction::Continue(mut arguments) => {
    //         match target_session_proc(&mut arguments).wrap_err("During logon session select")? {
    //             ProcessFlowInstruction::Terminate => return Ok(()),
    //             ProcessFlowInstruction::Continue(_) => {
    //                 match launch_process(arguments).wrap_err("During child process setup")? {
    //                     _ => Ok(()),
    //                 }
    //             }
    //         }
    //     }
    // }
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

fn target_session_snapshot(args: &mut Arguments) -> Result<u32> {
    let guard = WrappedImpersonation::impersonate_self(SecurityImpersonation.0)?;

    let current_thread = WrappedHandle::new_from_current_thread()?;
    let thread_token =
        current_thread.new_token((TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY).0, false)?;
    enable_privilege(&thread_token, &SE_DEBUG_NAME)?;

    let snapshot_processes =
        unsafe { WrappedHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?) };


    let mut current = PROCESSENTRY32W::default();
    current.dwSize = size_of_val(&current)
        .try_into()
        .expect("Integer overflow at PROCESSENTRY32W");
    unsafe { Process32FirstW(*snapshot_processes.get(), addr_of_mut!(current)).ok()? };

    let mut first = true;
    loop {        
        // NOTE; Workaround for lack of do-while in Rust syntax.
        if mem::replace(&mut first, false) == false
        && match unsafe {
            Process32NextW(*snapshot_processes.get(), addr_of_mut!(current)).ok()
        } {
            Ok(_) => {
                /* Move into next iteration */
                false
            }
            Err(error) => match WIN32_ERROR::from_error(&error) {
                Some(ERROR_NO_MORE_FILES) => true,
                _ => Err(error)?,
            },
        }
        {
            break;
        }
        
        dbg!(current.th32ProcessID);
        dbg!(current.th32ParentProcessID);
        let Ok(target_process) = 
        WrappedHandle::new_from_external_process(current.th32ProcessID, PROCESS_QUERY_INFORMATION.0)
        .or_else(|_| WrappedHandle::new_from_external_process(current.th32ProcessID, PROCESS_QUERY_LIMITED_INFORMATION.0))
        else {
            continue;
        };

        let desired_process_token_access =
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY;
        let Ok(target_process_token) = target_process.new_token(desired_process_token_access.0)
        .or_else(|_| target_process.new_token((desired_process_token_access & !TOKEN_QUERY_SOURCE).0))
        else {
            continue;
        };

        let groups_info = TokenInformation::<TOKEN_GROUPS>::new(&target_process_token)?;
        for group in groups_info.get_groups() {
            let sid_string = unsafe {
                let mut wide_string = PWSTR::null();
                ConvertSidToStringSidW(group.Sid, addr_of_mut!(wide_string)).ok()?;
                String::from_utf16_lossy(wide_string.as_wide())
            };
            println!("{sid_string}");
        }

        return Ok(0);
    }

    guard.revert()?;
    Err(eyre!("Not found"))
}

fn target_session_proc(args: &mut Arguments) -> Result<ProcessFlowInstruction<u32>> {
    let mut process_ids = Vec::<u32>::with_capacity(1024);
    let available_buffer = (process_ids.capacity() * size_of::<u32>())
        .try_into()
        .expect("Integer overflow at EnumProcesses");
    let mut consumed_buffer = 0;

    unsafe {
        EnumProcesses(
            process_ids.as_mut_ptr(),
            available_buffer,
            addr_of_mut!(consumed_buffer),
        )
        .ok()?;
    }

    if available_buffer == consumed_buffer {
        return Err(eyre!("Didn't provide enough buffer space to enumerate all processes on this system. This is a programmer's mistake!"));
    }

    let filled_items = consumed_buffer as usize / size_of::<u32>();
    let process_ids: &[u32] = unsafe { from_raw_parts(process_ids.as_ptr().cast(), filled_items) };

    println!(
        "Process IDs: {:?}",
        process_ids.iter().take(10).collect::<Vec<_>>()
    );

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
