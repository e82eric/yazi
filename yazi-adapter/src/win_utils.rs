#[cfg(windows)]
use std::ffi::OsString;
use std::ptr::null_mut;
use std::os::windows::ffi::OsStringExt;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
use winapi::um::winnt::PROCESS_VM_READ;
use winapi::shared::minwindef::FALSE;

fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if process_handle.is_null() {
            return None;
        }

        let mut buffer: [u16; 260] = [0; 260];
        let length = GetModuleBaseNameW(process_handle, null_mut(), buffer.as_mut_ptr(), 260 as u32);
        CloseHandle(process_handle);

        if length == 0 {
            return None;
        }

        let name: OsString = OsString::from_wide(&buffer[..length as usize]);
        name.into_string().ok()
    }
}

fn get_parent_process_id(pid: u32) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) == FALSE {
            CloseHandle(snapshot);
            return None;
        }

        while entry.th32ProcessID != pid {
            if Process32NextW(snapshot, &mut entry) == FALSE {
                CloseHandle(snapshot);
                return None;
            }
        }

        let parent_pid = entry.th32ParentProcessID;
        CloseHandle(snapshot);
        Some(parent_pid)
    }
}

fn is_microsoft_inner(current_pid: u32) -> bool {
    match get_parent_process_id(current_pid).and_then(get_process_name) {
        Some(name) => {
            let name = name.to_lowercase();
            //There are probably more variants of conhost that should be added here
            //windbg seems to have its own variant of conhost and there are probably others
            if ["conhost", "windowsterminal", "openconsole"].iter().any(|s| name.contains(s)) {
                true
            } else if name.contains("wezterm") {
                false
            } else {
                is_microsoft_inner(get_parent_process_id(current_pid).unwrap())
            }
        }
        None => false, // We are at the end of the parent tree.  Guessing this is an
        // unknown terminal running on windows
    }
}

pub fn is_microsoft() -> bool {
    let current_pid = unsafe { GetCurrentProcessId() };
    let result = is_microsoft_inner(current_pid);
    result
}
