#[cfg(not(windows))]
compile_error!("This project only works on Windows systems!");

use std::{
    ffi::{OsStr, OsString},
    marker::PhantomData,
    mem::{self, size_of},
    os::windows::prelude::OsStrExt,
    ptr::{addr_of, addr_of_mut},
    slice::from_raw_parts,
};

use thiserror::Error;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_IMPERSONATION_TOKEN, ERROR_NO_TOKEN,
            HANDLE, LUID, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, GetTokenInformation, ImpersonateSelf, LookupPrivilegeValueW,
            RevertToSelf, TokenGroups, LUID_AND_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
            SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
            PROCESS_ACCESS_RIGHTS,
        },
    },
};

pub enum ProcessFlowInstruction<PayloadType> {
    Continue(PayloadType),
    Terminate,
}

#[cfg(windows)]
fn should_quote_string(string: &OsStr) -> bool {
    // TODO; These values are probably const-able
    let _space: Vec<_> = OsStr::new(" ").encode_wide().collect();
    let _quotation_mark: Vec<_> = OsStr::new("\"").encode_wide().collect();

    let string_bytes: Vec<_> = string.encode_wide().collect();
    if string_bytes.len() == 0 {
        return false;
    }

    let has_spaces = string_bytes[..]
        .windows(_space.len())
        .position(|window| *window == *_space)
        .is_some();
    let start_quotation = string_bytes[.._quotation_mark.len()] == *_quotation_mark;
    let end_quotation =
        string_bytes[(string_bytes.len() - _quotation_mark.len())..] == *_quotation_mark;

    !start_quotation && !end_quotation && has_spaces
}

pub fn reconstruct_command_line(components: &Vec<OsString>) -> Option<Vec<u16>> {
    let _quotation_mark = OsStr::new("\"");
    let _space = OsStr::new(" ");
    let expected_length: usize = components.iter().map(|component| component.len() + 2).sum();

    let reconstructed: Vec<_> = components
        .iter()
        .fold(
            OsString::with_capacity(expected_length),
            |mut collector, component| {
                if should_quote_string(&component) {
                    collector.extend([
                        _quotation_mark,
                        component.as_os_str(),
                        _quotation_mark,
                        _space,
                    ]);
                } else {
                    collector.extend([component.as_os_str(), _space]);
                }

                collector
            },
        )
        .encode_wide()
        .chain(Some(0))
        .collect();

    // NOTE; Nothing is returned when the parts make no syntactically correct
    // commandline.
    if reconstructed.len() > 1 {
        Some(reconstructed)
    } else {
        None
    }
}

#[derive(Error, Debug)]
pub enum ImpersonationError {
    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub struct WrappedImpersonation;
pub struct ImpersonationGuard {
    dropped: bool,
}

impl WrappedImpersonation {
    pub fn impersonate_self(
        impersonation_level: i32,
    ) -> Result<ImpersonationGuard, ImpersonationError> {
        match unsafe { ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL(impersonation_level)).ok() } {
            Ok(_) => Ok(ImpersonationGuard { dropped: false }),
            Err(error) => Err(error)?,
        }
    }
}

impl ImpersonationGuard {
    pub fn revert(mut self) -> Result<(), ImpersonationError> {
        if mem::replace(&mut self.dropped, true) == false {
            unsafe { RevertToSelf().ok()? };
        }

        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if mem::replace(&mut self.dropped, true) == false {
            unsafe { RevertToSelf() };
        }
    }
}

#[derive(Error, Debug)]
pub enum PrivilegeError {
    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub fn enable_privileges(
    token: &WrappedHandle<ThreadToken>,
    privileges_to_enable: &[PCWSTR],
) -> Result<(), PrivilegeError> {
    // Let's not do the funky thing and alloc TOKEN_PRIVILEGES ourselves!
    // TOKEN_PRIVILEGES is a variable sized structure, but the API mapped it to fixed length with 1
    // LUID payload.
    privileges_to_enable
        .iter()
        .map(|privilege| enable_privilege(token, privilege))
        .collect()
}

pub fn enable_privilege(
    token: &WrappedHandle<ThreadToken>,
    privilege_to_enable: &PCWSTR,
) -> Result<(), PrivilegeError> {
    let mut privilege_wrapper = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Attributes: SE_PRIVILEGE_ENABLED,
            Luid: Default::default(),
        }],
    };

    unsafe {
        LookupPrivilegeValueW(
            None,
            *privilege_to_enable,
            addr_of_mut!(privilege_wrapper.Privileges[0].Luid),
        )
        .ok()?;
    }

    unsafe {
        AdjustTokenPrivileges(
            *token.get(),
            false,
            Some(addr_of!(privilege_wrapper)),
            0,
            None,
            None,
        )
        .ok()?;
    }

    // TODO; Check WinLastError again!

    Ok(())
}

pub fn disable_privilege(
    handle: &WrappedHandle,
    privilege_to_enable: &PCWSTR,
) -> Result<(), PrivilegeError> {
    let mut privilege_wrapper = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Attributes: Default::default(), // <- Disable privilege
            Luid: Default::default(),
        }],
    };

    unsafe {
        LookupPrivilegeValueW(
            None,
            *privilege_to_enable,
            addr_of_mut!(privilege_wrapper.Privileges[0].Luid),
        )
        .ok()?;
    }

    unsafe {
        AdjustTokenPrivileges(
            *handle.get(),
            false,
            Some(addr_of!(privilege_wrapper)),
            0,
            None,
            None,
        )
        .ok()?;
    }

    // TODO; Check WinLastError again!

    Ok(())
}

#[derive(Error, Debug)]
pub enum WrappedHandleError {
    #[error("You tried retrieving the impersonating token from a thread, but none was set")]
    NoThreadTokenSet,

    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub struct Process;
pub struct ProcessToken;
pub struct Thread;
pub struct ThreadToken;

pub struct WrappedHandle<Token = ()> {
    handle: HANDLE,
    _phantom: PhantomData<Token>,
}

impl WrappedHandle {
    pub unsafe fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            _phantom: PhantomData,
        }
    }

    pub fn new_from_current_process() -> Result<WrappedHandle<Process>, WrappedHandleError> {
        let handle = unsafe { GetCurrentProcess() };

        Ok(WrappedHandle {
            handle,
            _phantom: PhantomData,
        })
    }

    pub fn new_from_external_process(
        process_id: u32,
        process_access_rights: u32,
    ) -> Result<WrappedHandle<Process>, WrappedHandleError> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS(process_access_rights),
                false,
                process_id,
            )?
        };

        Ok(WrappedHandle {
            handle,
            _phantom: PhantomData,
        })
    }

    pub fn new_from_current_thread() -> Result<WrappedHandle<Thread>, WrappedHandleError> {
        // WARN; Thread handle doesn't need closing! It's a so called pseudo handle.
        // But calling CloseHandle on this handle is a noop, so no issues.
        let handle = unsafe { GetCurrentThread() };

        Ok(WrappedHandle {
            handle,
            _phantom: PhantomData,
        })
    }
}

impl<Token> WrappedHandle<Token> {
    pub unsafe fn get(&self) -> &HANDLE {
        &self.handle
    }
}

impl WrappedHandle<Process> {
    pub fn new_token(
        &self,
        token_access_rights: u32,
    ) -> Result<WrappedHandle<ProcessToken>, WrappedHandleError> {
        let mut handle: HANDLE = Default::default();
        unsafe {
            if let Err(error) = OpenProcessToken(
                self.handle,
                TOKEN_ACCESS_MASK(token_access_rights),
                addr_of_mut!(handle),
            )
            .ok()
            {
                match WIN32_ERROR::from_error(&error) {
                    Some(ERROR_NO_TOKEN) | Some(ERROR_NO_IMPERSONATION_TOKEN) => {
                        Err(WrappedHandleError::NoThreadTokenSet)?
                    }
                    _ => Err(error)?,
                }
            }
        };

        Ok(WrappedHandle {
            handle,
            _phantom: PhantomData,
        })
    }
}

impl WrappedHandle<ProcessToken> {}

impl WrappedHandle<Thread> {
    pub fn new_token(
        &self,
        token_access_rights: u32,
        open_with_impersonation: bool,
    ) -> Result<WrappedHandle<ThreadToken>, WrappedHandleError> {
        let mut handle: HANDLE = Default::default();
        unsafe {
            OpenThreadToken(
                self.handle,
                TOKEN_ACCESS_MASK(token_access_rights),
                !open_with_impersonation,
                addr_of_mut!(handle),
            )
            .ok()?
        };

        Ok(WrappedHandle {
            handle,
            _phantom: PhantomData,
        })
    }
}

impl WrappedHandle<ThreadToken> {}

impl<Token> Drop for WrappedHandle<Token> {
    fn drop(&mut self) {
        // SAFETY; Safe because this wrapper only stores unique and valid handles created within.
        unsafe { CloseHandle(self.handle) };
    }
}

pub trait TokenClass {
    fn class() -> TOKEN_INFORMATION_CLASS;
}

impl TokenClass for TOKEN_GROUPS {
    fn class() -> TOKEN_INFORMATION_CLASS {
        TokenGroups
    }
}

#[derive(Error, Debug)]
pub enum TokenInformationError {
    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub struct TokenInformation<Token> {
    info_buffer: Vec<u8>,
    _phantom: PhantomData<Token>,
}

impl<Class: TokenClass> TokenInformation<Class> {
    pub fn new(handle: &WrappedHandle<ProcessToken>) -> Result<Self, TokenInformationError> {
        let mut required_size = 0;
        unsafe {
            match GetTokenInformation(
                *handle.get(),
                Class::class(),
                None,
                0,
                addr_of_mut!(required_size),
            )
            .ok()
            {
                Ok(_) => unreachable!("This API call is setup to fail!"),
                Err(error) => match WIN32_ERROR::from_error(&error) {
                    Some(ERROR_INSUFFICIENT_BUFFER) => { /* Expected error */ }
                    _ => return Err(TokenInformationError::Other(error)),
                },
            };
        }

        let mut info_buffer = Vec::<u8>::with_capacity(required_size as usize);
        required_size = 0;
        unsafe {
            GetTokenInformation(
                *handle.get(),
                Class::class(),
                Some(info_buffer.as_mut_ptr().cast()),
                (info_buffer.capacity() * size_of::<u8>()) as _,
                addr_of_mut!(required_size),
            )
            .ok()?;
        }

        Ok(Self {
            info_buffer,
            _phantom: PhantomData::default(),
        })
    }
}

impl<Class> AsRef<Class> for TokenInformation<Class> {
    fn as_ref(&self) -> &Class {
        // SAFETY; Safe because object construction is bound to generic argument and the buffer is
        // completely abstracted behind a type interface.
        let info: &[Class] = unsafe { from_raw_parts(self.info_buffer.as_ptr().cast(), 1) };
        &info[0]
    }
}

// SAFETY; Cannot provide this interface without breaking other safe interfaces
// impl<Token> AsMut<Token> for TokenInformation<Token> {
//     fn as_mut(&mut self) -> &mut Token {
//         // SAFETY; Safe because object construction is bound to generic argument and the buffer is
//         // completely abstracted behind a type interface.
//         let info: &mut [Token] =
//             unsafe { from_raw_parts_mut(self.info_buffer.as_mut_ptr().cast(), 1) };
//         &mut info[0]
//     }
// }

impl TokenInformation<TOKEN_GROUPS> {
    pub fn get_groups(&self) -> &[SID_AND_ATTRIBUTES] {
        let object = self.as_ref();
        // SAFETY; Safe because Groups is a valid aligned pointer, and GroupCount came from the OS.
        unsafe { from_raw_parts(object.Groups.as_ptr(), object.GroupCount as _) }
    }
}
