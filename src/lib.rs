#[cfg(not(windows))]
compile_error!("This project only works on Windows systems!");

use std::{
    ffi::{OsStr, OsString},
    os::windows::prelude::OsStrExt,
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
