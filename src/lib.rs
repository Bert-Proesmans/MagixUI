#[cfg(not(windows))]
compile_error!("This project only works on Windows systems!");

use std::{
    ffi::{OsStr, OsString},
    fmt::Debug,
    marker::PhantomData,
    mem::{self, size_of_val},
    os::windows::prelude::{OsStrExt, OsStringExt},
    path::PathBuf,
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
            AdjustTokenPrivileges, DuplicateTokenEx, EqualSid, GetTokenInformation,
            ImpersonateSelf, LookupAccountNameW, LookupPrivilegeValueW, RevertToSelf,
            SecurityImpersonation, TokenGroups, TokenPrimary, TokenUser, LUID_AND_ATTRIBUTES,
            SECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, SE_PRIVILEGE_ENABLED,
            SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_ACCESS_MASK, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES, TOKEN_USER,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            SystemServices::MAXIMUM_ALLOWED,
            Threading::{
                GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
                OpenThreadToken, QueryFullProcessImageNameW, PROCESS_ACCESS_RIGHTS,
                PROCESS_NAME_WIN32,
            },
        },
    },
};

pub enum ProcessFlowInstruction<PayloadType> {
    Continue(PayloadType),
    Terminate,
}

#[inline]
pub fn contains_wide(haystack: &[u16], needle: &[u16]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[inline]
pub fn find_last_quote_occurence(haystack: &OsStr) -> Option<(usize, bool)> {
    let haystack: Vec<_> = haystack.encode_wide().collect();
    let needle: Vec<_> = "\"".encode_utf16().collect();
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle.as_slice())
        .map(|position| (position, haystack.len() == position + needle.len()))
}

#[inline]
pub fn find_first_quote_occurence(haystack: &OsStr) -> Option<(usize, bool)> {
    let haystack: Vec<_> = haystack.encode_wide().collect();
    let needle: Vec<_> = "\"".encode_utf16().collect();
    haystack
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
        .map(|position| (position, position == 0))
}

#[inline]
pub fn find_last_separator_occurence(haystack: &OsStr) -> Option<(usize, bool)> {
    let haystack: Vec<_> = haystack.encode_wide().collect();
    let needle: Vec<_> = "\\".encode_utf16().collect();
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle.as_slice())
        .map(|position| (position, haystack.len() == position + needle.len()))
}

#[inline]
pub fn find_first_separator_occurence(haystack: &OsStr) -> Option<(usize, bool)> {
    let haystack: Vec<_> = haystack.encode_wide().collect();
    let needle: Vec<_> = "\\".encode_utf16().collect();
    haystack
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
        .map(|position| (position, position == 0))
}

fn should_quote_string(haystack_string: &OsStr) -> bool {
    let haystack: Vec<_> = haystack_string.encode_wide().collect();

    let space_needle: Vec<_> = " ".encode_utf16().collect();
    let has_space = contains_wide(&haystack, &space_needle);
    let starts_with_quote = matches!(find_first_quote_occurence(haystack_string), Some((_, true)));
    let ends_with_quote = matches!(find_last_quote_occurence(haystack_string), Some((_, true)));

    has_space && (!starts_with_quote || !ends_with_quote)
}

pub fn create_command_line_widestring(components: &Vec<OsString>) -> Option<Vec<u16>> {
    let quote = OsStr::new("\"");
    let space = OsStr::new(" ");
    let constructed = components.iter().fold(OsString::new(), |mut collector, component| {
        if should_quote_string(&component) {
            collector.extend([quote, component, quote, space]);
        } else {
            collector.extend([component, space]);
        }

        collector
    });

    // WARN; Don't return anything if the command line is empty
    match constructed.len() > 1 {
        true => Some(constructed.encode_wide().collect()),
        false => None,
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

    LookupPrivilegeValueW(None, privilege_to_enable, &mut privilege_wrapper.Privileges[0].Luid)
        .ok()
        .map_err(|_| {
            let privilege_string =
                privilege_to_enable.to_string().unwrap_or_else(|_| "[Decode error]".into());
            PrivilegeError::InvalidPrivilegeName(privilege_string)
        })?;

    unsafe { AdjustTokenPrivileges(*token.get(), false, Some(&privilege_wrapper), 0, None, None) }
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

    LookupPrivilegeValueW(None, privilege_to_disable, &mut privilege_wrapper.Privileges[0].Luid)
        .ok()?;

    AdjustTokenPrivileges(*handle.get(), false, Some(&privilege_wrapper), 0, None, None).ok()?;

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

impl<Token> Debug for WrappedHandle<Token> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedHandle").field("handle", &self.handle).finish()
    }
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
            if let Err(error) =
                OpenProcessToken(self.handle, TOKEN_ACCESS_MASK(token_access_rights), &mut handle)
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

    pub fn get_process_image_path(&self) -> Result<PathBuf, WrappedHandleError> {
        let mut available_codepoints: u32 =
            (1 << 7).try_into().expect("Integer overflow at QueryFullProcessImageName");
        let mut buffer = Vec::<u16>::with_capacity(available_codepoints as usize);

        loop {
            unsafe {
                match QueryFullProcessImageNameW(
                    self.handle,
                    PROCESS_NAME_WIN32,
                    PWSTR::from_raw(buffer.as_mut_ptr()),
                    &mut available_codepoints,
                )
                .ok()
                {
                    Ok(_) => break,
                    Err(error) => match WIN32_ERROR::from_error(&error) {
                        Some(ERROR_INSUFFICIENT_BUFFER) => { /* Expected error */ }
                        _ => return Err(WrappedHandleError::Other(error)),
                    },
                };
            }

            // Retry with a bigger buffer
            available_codepoints = available_codepoints
                .checked_shl(1)
                .expect("Integer overflow at QueryFullProcessImageName");
            // WARN; The len value is never updated, so reserve will function as if available_codepoints
            // is an absolute value.
            buffer.reserve(available_codepoints as usize);
        }

        let wide_string = PWSTR::from_raw(buffer.as_mut_ptr());
        let wide_string = OsString::from_wide(unsafe { wide_string.as_wide() });
        Ok(PathBuf::from(wide_string))
    }
}

impl WrappedHandle<ProcessToken> {
    pub fn duplicate_impersonation(&self) -> Result<Self, WrappedHandleError> {
        let mut security_attributes = SECURITY_ATTRIBUTES::default();
        security_attributes.nLength = size_of_val(&security_attributes)
            .try_into()
            .expect("Integer overflow at SECURITY_ATTRIBUTES");
        security_attributes.bInheritHandle = false.into();

        let mut duplicated_handle = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                self.handle,
                TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
                Some(&security_attributes),
                SecurityImpersonation,
                TokenPrimary,
                &mut duplicated_handle,
            )
            .ok()?;
        }

        Ok(Self { handle: duplicated_handle, _phantom: PhantomData })
    }
}

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
                &mut handle,
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
            match GetTokenInformation(*handle.get(), Class::class(), None, 0, &mut required_size)
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
                &mut sid_required_size,
                PWSTR::null(),
                &mut host_required_size,
                &mut sid_usage,
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
                &mut sid_required_size,
                PWSTR::from_raw(host_info_buffer.as_mut_ptr()),
                &mut host_required_size,
                &mut sid_usage,
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
            false => unsafe { Process32FirstW(*self.snapshot_handle.get(), &mut current_entry) },
            true => unsafe { Process32NextW(*self.snapshot_handle.get(), &mut current_entry) },
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
