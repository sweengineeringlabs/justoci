use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

pub struct RegistryGuard {
    pub addr: String,
    _proc: Child,
    _storage: TempDir,
}

impl RegistryGuard {
    pub fn start() -> Self {
        which_regis();

        let port = free_port();
        let addr = format!("127.0.0.1:{port}");

        let storage = TempDir::new().expect("registry_guard: failed to create storage dir");
        let storage_str = storage.path().to_str().expect("storage path is valid utf-8").to_owned();

        let proc = Command::new("regis")
            .args(["serve", "--listen", &addr, "--storage", &storage_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("registry_guard: failed to spawn regis");

        wait_ready(&addr);
        crate::api::set_registry_override(addr.clone());

        Self { addr, _proc: proc, _storage: storage }
    }
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        let _ = self._proc.kill();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .expect("registry_guard: failed to bind ephemeral port");
    let port = listener
        .local_addr()
        .expect("registry_guard: failed to get local addr")
        .port();
    drop(listener);
    port
}

fn wait_ready(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("registry_guard: regis did not become ready within 10 s at {addr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn which_regis() {
    Command::new("regis")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|_| panic!(
            "bench: 'regis' not found on PATH\n\
             Build xikaftin and add regis to your PATH:\n\
             cargo build -p regis --release  (in the xikaftin workspace)"
        ));
}
