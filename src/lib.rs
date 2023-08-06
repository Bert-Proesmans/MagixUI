#[cfg(not(windows))]
compile_error!("This project only works on Windows systems!");

use std::{
    ffi::{OsStr, OsString},
    marker::PhantomData,
    mem::{self, size_of_val},
    os::windows::prelude::OsStrExt,
    ptr::{addr_of, addr_of_mut},
    slice::from_raw_parts,
};

use thiserror::Error;
use windows::{
    core::{Error, PCWSTR, PWSTR},
    w,
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED,
            ERROR_NO_IMPERSONATION_TOKEN, ERROR_NO_MORE_FILES, ERROR_NO_TOKEN, HANDLE, PSID,
            WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, EqualSid, GetTokenInformation, ImpersonateSelf,
            LookupAccountNameW, LookupPrivilegeValueW, RevertToSelf, TokenGroups, TokenUser,
            LUID_AND_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, SE_PRIVILEGE_ENABLED,
            SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_ACCESS_MASK, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES, TOKEN_USER,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
                OpenThreadToken, PROCESS_ACCESS_RIGHTS,
            },
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

    let has_spaces =
        string_bytes[..].windows(_space.len()).position(|window| *window == *_space).is_some();
    let start_quotation = string_bytes[.._quotation_mark.len()] == *_quotation_mark;
    let end_quotation =
        string_bytes[(string_bytes.len() - _quotation_mark.len())..] == *_quotation_mark;

    !start_quotation && !end_quotation && has_spaces
}

// TODO; Recheck invariants
pub fn reconstruct_command_line(components: &Vec<OsString>) -> Option<Vec<u16>> {
    let _quotation_mark = OsStr::new("\"");
    let _space = OsStr::new(" ");
    let expected_length: usize = components.iter().map(|component| component.len() + 2).sum();

    let reconstructed: Vec<_> = components
        .iter()
        .fold(OsString::with_capacity(expected_length), |mut collector, component| {
            if should_quote_string(&component) {
                collector.extend([_quotation_mark, component.as_os_str(), _quotation_mark, _space]);
            } else {
                collector.extend([component.as_os_str(), _space]);
            }

            collector
        })
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
            if let Err(error) = unsafe { RevertToSelf().ok() } {
                panic!(
                    "RevertToSelf call failed, aborting thread now! Error message {0}",
                    error.message()
                );
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum PrivilegeError {
    #[error("The provided privilege name '{0}' is unknown.")]
    InvalidPrivilegeName(String),

    #[error("The privilege with name '{0}' could not be enabled.")]
    PrivilegeNotEnabled(String),

    #[error("The privilege with name '{0}' could not be disabled.")]
    PrivilegeNotDisabled(String),

    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

// It pains me to create this leaky interface :s
// Accepting PCWSTR also means I must make this method unsafe -_-
pub unsafe fn enable_privileges(
    token: &WrappedHandle<ThreadToken>,
    privileges_to_enable: &[PCWSTR],
) -> Result<(), PrivilegeError> {
    // Let's not do the funky thing and alloc TOKEN_PRIVILEGES ourselves!
    // TOKEN_PRIVILEGES is a variable sized structure, but the API mapped it to fixed length with 1
    // LUID payload.
    privileges_to_enable.iter().map(|privilege| enable_privilege(token, *privilege)).collect()
}

// It pains me to create this leaky interface :s
// Accepting PCWSTR also means I must make this method unsafe -_-
pub unsafe fn enable_privilege(
    token: &WrappedHandle<ThreadToken>,
    privilege_to_enable: PCWSTR,
) -> Result<(), PrivilegeError> {
    let mut privilege_wrapper = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Attributes: SE_PRIVILEGE_ENABLED,
            Luid: Default::default(),
        }],
    };

    LookupPrivilegeValueW(
        None,
        privilege_to_enable,
        addr_of_mut!(privilege_wrapper.Privileges[0].Luid),
    )
    .ok()
    .map_err(|_| {
        let privilege_string =
            privilege_to_enable.to_string().unwrap_or_else(|_| "[Decode error]".into());
        PrivilegeError::InvalidPrivilegeName(privilege_string)
    })?;

    unsafe {
        AdjustTokenPrivileges(*token.get(), false, Some(addr_of!(privilege_wrapper)), 0, None, None)
    }
    .ok()?;

    // ERROR; Need to double-check the set permissions! "AdjustTokenPrivileges" returns
    // status of the _request_ but not if all privileges are set. That's why a second test is needed!
    if Error::from_win32().code() == ERROR_NOT_ALL_ASSIGNED.to_hresult() {
        // NOTE; No need to reset privileges to consistent state because we update permission 1 by 1.
        let privilege_string =
            privilege_to_enable.to_string().unwrap_or_else(|_| "[Decode error]".into());
        Err(PrivilegeError::PrivilegeNotEnabled(privilege_string))?;
    }

    Ok(())
}

// It pains me to create this leaky interface :s
// Accepting PCWSTR also means I must make this method unsafe -_-
pub unsafe fn disable_privilege(
    handle: &WrappedHandle,
    privilege_to_disable: PCWSTR,
) -> Result<(), PrivilegeError> {
    let mut privilege_wrapper = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Attributes: Default::default(), // <- Disable privilege
            Luid: Default::default(),
        }],
    };

    LookupPrivilegeValueW(
        None,
        privilege_to_disable,
        addr_of_mut!(privilege_wrapper.Privileges[0].Luid),
    )
    .ok()?;

    AdjustTokenPrivileges(*handle.get(), false, Some(addr_of!(privilege_wrapper)), 0, None, None)
        .ok()?;

    // ERROR; Need to double-check the set permissions! "AdjustTokenPrivileges" returns
    // status of the _request_ but not if all privileges are set. That's why a second test is needed!
    if Error::from_win32().code() == ERROR_NOT_ALL_ASSIGNED.to_hresult() {
        // NOTE; No need to reset privileges to consistent state because we update permission 1 by 1.
        let privilege_string =
            privilege_to_disable.to_string().unwrap_or_else(|_| "[Decode error]".into());
        Err(PrivilegeError::PrivilegeNotDisabled(privilege_string))?;
    }

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
        Self { handle, _phantom: PhantomData }
    }

    pub fn new_from_current_process() -> Result<WrappedHandle<Process>, WrappedHandleError> {
        let handle = unsafe { GetCurrentProcess() };

        Ok(WrappedHandle { handle, _phantom: PhantomData })
    }

    pub fn new_from_external_process(
        process_id: u32,
        process_access_rights: u32,
    ) -> Result<WrappedHandle<Process>, WrappedHandleError> {
        let handle = unsafe {
            OpenProcess(PROCESS_ACCESS_RIGHTS(process_access_rights), false, process_id)?
        };

        Ok(WrappedHandle { handle, _phantom: PhantomData })
    }

    pub fn new_from_current_thread() -> Result<WrappedHandle<Thread>, WrappedHandleError> {
        // WARN; Thread handle doesn't need closing! It's a so called pseudo handle.
        // But calling CloseHandle on this handle is a noop, so no issues.
        let handle = unsafe { GetCurrentThread() };

        Ok(WrappedHandle { handle, _phantom: PhantomData })
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

        Ok(WrappedHandle { handle, _phantom: PhantomData })
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

        Ok(WrappedHandle { handle, _phantom: PhantomData })
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

impl TokenClass for TOKEN_USER {
    fn class() -> TOKEN_INFORMATION_CLASS {
        TokenUser
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
        unsafe {
            GetTokenInformation(
                *handle.get(),
                Class::class(),
                Some(info_buffer.as_mut_ptr().cast()),
                required_size,
                &mut 0,
            )
            .ok()?;
        }

        Ok(Self { info_buffer, _phantom: PhantomData::default() })
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
// impl<Token> AsMut<Token> for TokenInformation<Token> {}

impl TokenInformation<TOKEN_GROUPS> {
    pub fn get_groups(&self) -> &[SID_AND_ATTRIBUTES] {
        let object = self.as_ref();
        // SAFETY; Safe because Groups is a valid aligned pointer, and GroupCount came from the OS.
        unsafe { from_raw_parts(object.Groups.as_ptr(), object.GroupCount as _) }
    }
}

#[derive(Error, Debug)]
pub enum SIDError {
    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub struct WrappedSID {
    info_buffer: Vec<u8>,
}

impl WrappedSID {
    pub unsafe fn new_from_local_account(user_name: &OsStr) -> Result<Self, SIDError> {
        let user_name_buffer: Vec<_> = user_name.encode_wide().chain(Some(0)).collect();
        let mut sid_required_size = 0;
        let mut host_required_size = 0;
        let mut sid_usage = SID_NAME_USE::default();

        unsafe {
            match LookupAccountNameW(
                w!("."),
                PCWSTR::from_raw(user_name_buffer.as_ptr()),
                PSID::default(),
                addr_of_mut!(sid_required_size),
                PWSTR::null(),
                addr_of_mut!(host_required_size),
                addr_of_mut!(sid_usage),
            )
            .ok()
            {
                Ok(_) => unreachable!("This API call is setup to fail!"),
                Err(error) => match WIN32_ERROR::from_error(&error) {
                    Some(ERROR_INSUFFICIENT_BUFFER) => { /* Expected error */ }
                    _ => return Err(SIDError::Other(error)),
                },
            };
        }

        let mut sid_info_buffer = Vec::<u8>::with_capacity(sid_required_size as usize);
        let mut host_info_buffer = Vec::<u16>::with_capacity(
            host_required_size as usize / (mem::size_of::<u16>() / mem::size_of::<u8>()),
        );
        unsafe {
            LookupAccountNameW(
                w!("."),
                PCWSTR::from_raw(user_name_buffer.as_ptr()),
                PSID(sid_info_buffer.as_mut_ptr().cast()),
                addr_of_mut!(sid_required_size),
                PWSTR::from_raw(host_info_buffer.as_mut_ptr()),
                addr_of_mut!(host_required_size),
                addr_of_mut!(sid_usage),
            )
            .ok()?;
        }

        sid_info_buffer.set_len(sid_info_buffer.capacity());
        Ok(Self { info_buffer: sid_info_buffer })
    }
}

impl PartialEq for WrappedSID {
    fn eq(&self, other: &Self) -> bool {
        self.info_buffer == other.info_buffer
    }
}

impl PartialEq<PSID> for WrappedSID {
    fn eq(&self, other: &PSID) -> bool {
        let self_sid = PSID(self.info_buffer.as_ptr().cast_mut().cast());
        unsafe { EqualSid(self_sid, *other).into() }
    }
}

impl AsRef<[u8]> for WrappedSID {
    fn as_ref(&self) -> &[u8] {
        &self.info_buffer
    }
}

#[derive(Error, Debug)]
pub enum ProcessSnapshotError {
    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub struct ProcessSnapshot {
    snapshot_handle: WrappedHandle,
    passed_first: bool,
}

impl ProcessSnapshot {
    pub fn new() -> Result<Self, ProcessSnapshotError> {
        let snapshot_handle =
            unsafe { WrappedHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?) };
        Ok(Self { snapshot_handle, passed_first: false })
    }
}

impl Iterator for ProcessSnapshot {
    type Item = Result<PROCESSENTRY32W, ProcessSnapshotError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut current_entry = PROCESSENTRY32W::default();
        current_entry.dwSize =
            size_of_val(&current_entry).try_into().expect("Integer overflow at PROCESSENTRY32W");

        let internal_operation = match mem::replace(&mut self.passed_first, true) {
            false => unsafe {
                Process32FirstW(*self.snapshot_handle.get(), addr_of_mut!(current_entry))
            },
            true => unsafe {
                Process32NextW(*self.snapshot_handle.get(), addr_of_mut!(current_entry))
            },
        };

        match internal_operation.ok() {
            Ok(_) => { /* No issue */ }
            Err(internal_error) => match WIN32_ERROR::from_error(&internal_error) {
                Some(ERROR_NO_MORE_FILES) => return None,
                _ => return Some(Err(internal_error.into())),
            },
        };

        Some(Ok(current_entry))
    }
}
