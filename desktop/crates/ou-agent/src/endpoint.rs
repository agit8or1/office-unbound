//! The agent's local IPC endpoint.
//!
//! Windows: a named pipe whose name contains 128 random bits, published only in `%LOCALAPPDATA%\OfficeUnbound\agent.endpoint`
//! (readable by the user alone), created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, remote clients rejected, and a DACL granting
//! access to the owner and SYSTEM only. Another user can neither guess the name nor connect; a stale or squatted name makes
//! the agent fail closed (it picks a new random name).
//! Unix (development): a socket in a 0700 directory with mode 0600.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};

pub const ENDPOINT_FILE: &str = "agent.endpoint";

pub trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

pub fn endpoint_file(root: &Path) -> PathBuf {
    root.join(ENDPOINT_FILE)
}

fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(content.as_bytes())
    }
    #[cfg(not(unix))]
    {
        // %LOCALAPPDATA% inherits a user-only ACL by default.
        std::fs::write(path, content)
    }
}

#[cfg(unix)]
pub mod imp {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    pub struct Server {
        l: UnixListener,
        path: PathBuf,
    }

    impl Server {
        pub fn bind(root: &Path) -> std::io::Result<Self> {
            let dir = root.join("run");
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let path = dir.join("agent.sock");
            if path.exists() {
                // A live agent answers; a stale socket does not.
                if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                    return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "agent already running"));
                }
                std::fs::remove_file(&path)?;
            }
            let l = UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            write_private(&endpoint_file(root), &path.to_string_lossy())?;
            Ok(Self { l, path })
        }

        pub async fn accept(&mut self) -> std::io::Result<Box<dyn Conn>> {
            let (s, _) = self.l.accept().await?;
            Ok(Box::new(s))
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub async fn connect(root: &Path) -> std::io::Result<Box<dyn Conn>> {
        let p = std::fs::read_to_string(endpoint_file(root))?;
        Ok(Box::new(UnixStream::connect(p.trim()).await?))
    }
}

#[cfg(windows)]
pub mod imp {
    use super::*;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    /// Owner Rights (OW) and LocalSystem (SY) full access; protected DACL (no inheritance), so Everyone/Anonymous get nothing.
    const SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";

    pub struct Server {
        name: String,
        next: NamedPipeServer,
    }

    fn create(name: &str, first: bool) -> std::io::Result<NamedPipeServer> {
        let sddl: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated SDDL; `sd` is freed with LocalFree after the pipe is created.
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let r = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .max_instances(8)
                .create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut core::ffi::c_void)
        };
        unsafe { LocalFree(sd as _) };
        r
    }

    impl Server {
        pub fn bind(root: &Path) -> std::io::Result<Self> {
            // An agent already running answers on the published name.
            if let Ok(old) = std::fs::read_to_string(endpoint_file(root)) {
                if ClientOptions::new().open(old.trim()).is_ok() {
                    return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "agent already running"));
                }
            }
            let name = format!(r"\\.\pipe\OfficeUnbound.Agent.{}", ou_core::oidc::random_token(16));
            let next = create(&name, true)?;
            write_private(&endpoint_file(root), &name)?;
            Ok(Self { name, next })
        }

        pub async fn accept(&mut self) -> std::io::Result<Box<dyn Conn>> {
            self.next.connect().await?;
            let fresh = create(&self.name, false)?;
            let conn = std::mem::replace(&mut self.next, fresh);
            Ok(Box::new(conn))
        }
    }

    pub async fn connect(root: &Path) -> std::io::Result<Box<dyn Conn>> {
        let p = std::fs::read_to_string(endpoint_file(root))?;
        Ok(Box::new(ClientOptions::new().open(p.trim())?))
    }
}

pub use imp::{connect, Server};
