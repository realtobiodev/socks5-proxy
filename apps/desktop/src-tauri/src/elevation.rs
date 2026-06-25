#[cfg(target_os = "windows")]
mod windows {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SID_IDENTIFIER_AUTHORITY,
    };
    use windows_sys::Win32::System::SystemServices::{
        DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    #[allow(dead_code)]
    pub fn relaunch_elevated_if_needed() {
        if is_elevated() {
            return;
        }

        match relaunch_elevated() {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                eprintln!("failed to request administrator privileges: {error}");
            }
        }
    }

    pub fn is_elevated() -> bool {
        unsafe {
            let mut administrators_group = null_mut();
            let nt_authority = SID_IDENTIFIER_AUTHORITY {
                Value: [0, 0, 0, 0, 0, 5],
            };
            let allocated = AllocateAndInitializeSid(
                &nt_authority,
                2,
                SECURITY_BUILTIN_DOMAIN_RID as u32,
                DOMAIN_ALIAS_RID_ADMINS as u32,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut administrators_group,
            );
            if allocated == 0 {
                return false;
            }

            let mut is_member = 0;
            let ok = CheckTokenMembership(null_mut(), administrators_group, &mut is_member);
            FreeSid(administrators_group);
            ok != 0 && is_member != 0
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn relaunch_elevated() -> Result<(), String> {
        let exe = std::env::current_exe()
            .map_err(|error| format!("failed to resolve current executable: {error}"))?;
        let args = std::env::args_os().skip(1).collect::<Vec<_>>();
        let params = quote_args(&args);
        let working_dir = exe
            .parent()
            .ok_or_else(|| "executable has no parent directory".to_string())?;

        let verb = wide_null(OsStr::new("runas"));
        let file = wide_null(exe.as_os_str());
        let params = wide_null(OsStr::new(&params));
        let directory = wide_null(working_dir.as_os_str());

        let result = unsafe {
            ShellExecuteW(
                HWND::default(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                directory.as_ptr(),
                SW_SHOWNORMAL,
            )
        } as isize;

        if result > 32 {
            Ok(())
        } else {
            Err(format!("ShellExecuteW returned {result}"))
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn quote_args(args: &[std::ffi::OsString]) -> String {
        args.iter()
            .map(|arg| quote_arg(&arg.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn quote_arg(arg: &str) -> String {
        if arg.is_empty() {
            return "\"\"".to_string();
        }
        if !arg
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\\'))
        {
            return arg.to_string();
        }

        let mut out = String::from("\"");
        let mut backslashes = 0;
        for ch in arg.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    out.push_str(&"\\".repeat(backslashes * 2 + 1));
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    out.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    out.push(ch);
                }
            }
        }
        out.push_str(&"\\".repeat(backslashes * 2));
        out.push('"');
        out
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::quote_arg;

        #[test]
        fn quotes_empty_arg() {
            assert_eq!(quote_arg(""), "\"\"");
        }

        #[test]
        fn leaves_simple_arg_unquoted() {
            assert_eq!(quote_arg("profile-1"), "profile-1");
        }

        #[test]
        fn quotes_whitespace_arg() {
            assert_eq!(quote_arg("hello world"), "\"hello world\"");
        }

        #[test]
        fn escapes_quotes_and_trailing_backslashes() {
            assert_eq!(quote_arg(r#"C:\tmp\say "hi"\"#), r#""C:\tmp\say \"hi\"\\""#);
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows::is_elevated;
#[cfg(target_os = "windows")]
pub use windows::relaunch_elevated_if_needed;

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn relaunch_elevated_if_needed() {}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn is_elevated() -> bool {
    false
}
