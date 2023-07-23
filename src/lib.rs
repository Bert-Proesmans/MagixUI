#[cfg(not(windows))]
compile_error!("This project only works on Windows systems!");

use std::{
    alloc::Layout,
    ffi::{OsStr, OsString},
    marker::PhantomData,
    mem::size_of_val,
    os::windows::prelude::OsStrExt,
    ptr::{addr_of, addr_of_mut},
    slice::{from_raw_parts, from_raw_parts_mut},
};

use thiserror::Error;
use windows::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, WIN32_ERROR},
    Security::{
        GetTokenInformation, TokenGroups, SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_GROUPS,
        TOKEN_INFORMATION_CLASS,
    },
    System::Threading::OpenProcessToken,
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
pub enum WrappedHandleError {
    #[error("The provided handle into a process is invalid")]
    InvalidProcessHandle,

    #[error(transparent)]
    Other(#[from] ::windows::core::Error), // source and Display delegate to ::windows::core::Error
}

pub struct WrappedHandle {
    handle: HANDLE,
}

impl WrappedHandle {
    pub unsafe fn get(&self) -> &HANDLE {
        &self.handle
    }

    pub fn from_process(process_handle: HANDLE) -> Result<Self, WrappedHandleError> {
        if process_handle.is_invalid() {
            return Err(WrappedHandleError::InvalidProcessHandle);
        }

        let mut handle: HANDLE = Default::default();
        unsafe {
            match OpenProcessToken(process_handle, TOKEN_ALL_ACCESS, addr_of_mut!(handle)).ok() {
                Ok(_) => Ok(Self { handle }),
                Err(error) => Err(WrappedHandleError::Other(error)),
            }
        }
    }
}

impl Drop for WrappedHandle {
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

impl<Token: TokenClass> TokenInformation<Token> {
    pub fn new(handle: &WrappedHandle) -> Result<Self, TokenInformationError> {
        let handle = unsafe { handle.get() };

        let mut required_size = 0;
        unsafe {
            match GetTokenInformation(
                handle.clone(),
                Token::class(),
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
                handle.clone(),
                Token::class(),
                Some(info_buffer.as_mut_ptr().cast()),
                size_of_val(info_buffer.as_slice()) as _,
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

impl<Token> AsRef<Token> for TokenInformation<Token> {
    fn as_ref(&self) -> &Token {
        // SAFETY; Safe because object construction is bound to generic argument and the buffer is
        // completely abstracted behind a type interface.
        let info: &[Token] = unsafe { from_raw_parts(self.info_buffer.as_ptr().cast(), 1) };
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
        unsafe { from_raw_parts(addr_of!(object.Groups[0]), object.GroupCount as _) }
    }
}
