use std::{
    ffi::{OsStr, OsString},
    mem::size_of_val,
    os::windows::prelude::OsStrExt,
    ptr::{self, addr_of},
};

use color_eyre::eyre::{eyre, Result, WrapErr};
use magixui::{reconstruct_command_line, ProcessFlowInstruction};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, SetFilePointerEx, FILE_ATTRIBUTE_NORMAL, FILE_END, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
        },
        System::Threading::{
            CreateProcessW, WaitForSingleObject, INFINITE, PROCESS_CREATION_FLAGS,
            PROCESS_INFORMATION, STARTF_USEHOTKEY, STARTF_USESTDHANDLES, STARTUPINFOW,
        },
    },
};

macro_rules! HELP {
    () => {
"\
Magix Forget

Launch a child process which doesn't exit when the parent process exits from the command line interface.

USAGE:
    {bin_name} [FLAGS] [OPTIONS] -- ProcessPath ProcessArgument1 ProcessArgument2 ProcessArgumentN

FLAGS:
    --help                          Prints help information and exits
    -w, --wait[=milliseconds]       Wait for the child process to exit before continuing, optionally wait for a provided amount of milliseconds
    --stdin=[Empty or File]         Attach the process 'standard input' file descriptor to the provided filepath or, if left empty, TODO
    --stdout=[Empty or File]        Attach the process 'standard output' file descriptor to the provided filepath or, if left empty, TODO
    --stderr=[Empty or File]        Attach the process 'standard error' file descriptor to the provided filepath or, if left empty, TODO

OPTIONS:
    # None yet

ARGS:
    --                              Argument splitter
    ProcessPath       PATH          The location of the process to execute
    ProcessArgumentN  STRING        Arguments passed to the proces on start
"
    };
}

struct Arguments {
    wait_for_child: Option<u32>,
    command_line: Vec<OsString>,
    startupinfo_mutators: Vec<IOHandleMutator>,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    match parse_args().wrap_err("During command line arguments parsing")? {
        ProcessFlowInstruction::Terminate => return Ok(()),
        ProcessFlowInstruction::Continue(arguments) => {
            match launch_process(arguments).wrap_err("During child process setup")? {
                _ => Ok(()),
            }
        }
    }
}

fn parse_args() -> Result<ProcessFlowInstruction<Arguments>, lexopt::Error> {
    use lexopt::prelude::*;
    let mut wait_for_child = None;
    let mut command_line = Vec::new();
    let mut startupinfo_mutators: Vec<IOHandleMutator> = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let bin_name = parser.bin_name().unwrap_or("yeet.exe");
                println!(HELP!(), bin_name = bin_name);
                return Ok(ProcessFlowInstruction::Terminate);
            }
            Short('w') | Long("wait") => {
                wait_for_child = match parser.optional_value() {
                    Some(millis) => Some(millis.parse()?),
                    None => Some(INFINITE),
                };
            }
            Long("stdin") => {
                let to = InputOutputReference::STDIN;
                match parser.optional_value() {
                    Some(path) if path.len() > 0 => {
                        let identification: InputOutputReference = path.as_os_str().into();
                        match identification {
                            InputOutputReference::UNDEFINED => startupinfo_mutators
                                .push(IOHandleMutator::FromFilepath { to, path }),
                            from => startupinfo_mutators
                                .push(IOHandleMutator::FromReference { to, from }),
                        };
                    }
                    _ => startupinfo_mutators.push(IOHandleMutator::FromReference {
                        to,
                        from: InputOutputReference::UNDEFINED,
                    }),
                };
            }
            Long("stdout") => {
                let to = InputOutputReference::STDOUT;
                match parser.optional_value() {
                    Some(path) if path.len() > 0 => {
                        let identification: InputOutputReference = path.as_os_str().into();
                        match identification {
                            InputOutputReference::UNDEFINED => startupinfo_mutators
                                .push(IOHandleMutator::FromFilepath { to, path }),
                            from => startupinfo_mutators
                                .push(IOHandleMutator::FromReference { to, from }),
                        }
                    }
                    _ => startupinfo_mutators.push(IOHandleMutator::FromReference {
                        to,
                        from: InputOutputReference::UNDEFINED,
                    }),
                };
            }
            Long("stderr") => {
                let to = InputOutputReference::STDERR;
                match parser.optional_value() {
                    Some(path) if path.len() > 0 => {
                        let identification: InputOutputReference = path.as_os_str().into();
                        match identification {
                            InputOutputReference::UNDEFINED => startupinfo_mutators
                                .push(IOHandleMutator::FromFilepath { to, path }),
                            from => startupinfo_mutators
                                .push(IOHandleMutator::FromReference { to, from }),
                        };
                    }
                    _ => startupinfo_mutators.push(IOHandleMutator::FromReference {
                        to,
                        from: InputOutputReference::UNDEFINED,
                    }),
                };
            }
            // NOTE; Everything after -- should be copied as is.
            // We will reconstruct the commandline string from these parts and pass into StartProcess
            Value(argument) => command_line.push(argument),
            _ => return Err(arg.unexpected()),
        };
    }

    Ok(ProcessFlowInstruction::Continue(Arguments {
        wait_for_child,
        command_line,
        startupinfo_mutators,
    }))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MutationOrder {
    First = 0,
    Last = 1,
}

enum IOHandleMutator {
    FromReference {
        to: InputOutputReference,
        from: InputOutputReference,
    },
    FromFilepath {
        to: InputOutputReference,
        path: OsString,
    },
}

impl IOHandleMutator {
    pub fn apply(
        &self,
        start_info: &mut STARTUPINFOW,
        security_attributes: &SECURITY_ATTRIBUTES,
    ) -> Result<()> {
        match self {
            IOHandleMutator::FromReference { to, from } => {
                let source = Self::get_io_handle_field_mut(start_info, from).cloned();
                let target = Self::get_io_handle_field_mut(start_info, to);
                match (target, source) {
                    (None, None) | (None, Some(_)) => {
                        Err(eyre!("Invalid IO reference combination"))
                    }
                    (Some(target), None) => {
                        *target = HANDLE::default();
                        Ok(())
                    }
                    (Some(target), Some(source)) => {
                        *target = source;

                        // NOTE; Setting IO handles requires flagging we use them to StartProcess
                        start_info.dwFlags &= !STARTF_USEHOTKEY; // ERROR; Incompatible with STARTF_USESTDHANDLES
                        start_info.dwFlags |= STARTF_USESTDHANDLES;

                        Ok(())
                    }
                }
            }
            IOHandleMutator::FromFilepath { to, path } => {
                // SAFETY; Filename buffer must be bound to stack to survive WINAPI call.
                let filename: Vec<_> = path.encode_wide().chain(Some(0)).collect();
                let read_access = match to {
                    InputOutputReference::STDIN => true,
                    _ => false,
                };

                let handle = unsafe {
                    let handle = CreateFileW(
                        // NOTE; Handles relative paths just fine.
                        PCWSTR::from_raw(filename.as_ptr()),
                        if read_access {
                            FILE_GENERIC_READ.0
                        } else {
                            FILE_GENERIC_WRITE.0
                        },
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        Some(security_attributes as *const _),
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        None,
                    )
                    .wrap_err("During IO file creation")?;
                    // Don't clobber existing data if we output into a file
                    if read_access == false {
                        SetFilePointerEx(handle, 0, None, FILE_END).ok()?;
                    }
                    handle
                };

                match Self::get_io_handle_field_mut(start_info, to) {
                    Some(target) => {
                        *target = handle;

                        // NOTE; Setting IO handles requires flagging to StartProcess
                        start_info.dwFlags &= !STARTF_USEHOTKEY; // ERROR; Incompatible with STARTF_USESTDHANDLES
                        start_info.dwFlags |= STARTF_USESTDHANDLES;

                        Ok(())
                    }
                    None => Err(eyre!("Invalid IO reference")),
                }
            }
        }
    }

    pub fn get_order(&self) -> MutationOrder {
        match self {
            IOHandleMutator::FromFilepath { .. } => MutationOrder::First,
            IOHandleMutator::FromReference { .. } => MutationOrder::Last,
        }
    }

    fn get_io_handle_field_mut<'start_info>(
        start_info: &'start_info mut STARTUPINFOW,
        field: &InputOutputReference,
    ) -> Option<&'start_info mut HANDLE> {
        match field {
            InputOutputReference::UNDEFINED => None,
            InputOutputReference::STDIN => Some(&mut start_info.hStdInput),
            InputOutputReference::STDOUT => Some(&mut start_info.hStdOutput),
            InputOutputReference::STDERR => Some(&mut start_info.hStdError),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputOutputReference {
    UNDEFINED,
    STDIN,
    STDOUT,
    STDERR,
}

impl From<&OsStr> for InputOutputReference {
    fn from(value: &OsStr) -> Self {
        match value.to_string_lossy() {
            std::borrow::Cow::Borrowed(str) => match str {
                "stdin" => Self::STDIN,
                "stdout" => Self::STDOUT,
                "stderr" => Self::STDERR,
                _ => Self::UNDEFINED,
            },
            _ => Self::UNDEFINED,
        }
    }
}

fn launch_process(mut args: Arguments) -> Result<ProcessFlowInstruction<()>> {
    let mut process_security_attributes = SECURITY_ATTRIBUTES::default();
    process_security_attributes.nLength = size_of_val(&process_security_attributes) as _;
    process_security_attributes.bInheritHandle = true.into();
    process_security_attributes.lpSecurityDescriptor = ptr::null_mut();

    let mut startup_info = STARTUPINFOW::default();
    startup_info.cb = size_of_val(&startup_info) as _;
    // WARN; If the child holds one of our handles open we won't be able to exit!
    // Inheriting is not enabled by default, only activated by using the CLI options.
    startup_info.dwFlags &= !STARTF_USESTDHANDLES;

    let mut command_line = match reconstruct_command_line(&args.command_line) {
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

    args.startupinfo_mutators.sort_by_key(|x| x.get_order());
    for mutator in args.startupinfo_mutators.iter() {
        mutator.apply(&mut startup_info, &process_security_attributes)?
    }
    println!("Child setup completed!");

    let mut process_info = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            None,
            PWSTR::from_raw(command_line.as_mut_ptr()),
            Some(addr_of!(process_security_attributes)),
            Some(addr_of!(process_security_attributes)),
            (startup_info.dwFlags & STARTF_USESTDHANDLES) == STARTF_USESTDHANDLES,
            PROCESS_CREATION_FLAGS(0),
            None, /* Pass through from parent */
            None, /* Pass through from parent */
            &mut startup_info,
            &mut process_info,
        )
        .ok()
        .wrap_err("During child process execution")?;
    };

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
