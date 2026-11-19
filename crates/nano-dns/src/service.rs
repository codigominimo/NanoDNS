//! Installation and lifecycle management for NanoDNS as an OS service.
//!
//! Both implementations use the same subcommands. Linux writes a hardened
//! systemd unit and delegates lifecycle operations to `systemctl`; Windows
//! registers the service in the SCM and hosts the Tokio runtime inside the
//! service control dispatcher. No Cargo features are involved: the target OS
//! is selected with `#[cfg]` at compile time.

/// Service name shared by the SCM and systemd units.
pub const SERVICE_NAME: &str = "NanoDNS";

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

#[cfg(unix)]
mod unix {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};

    use nano_dns_core::error::{Error, Result};

    const USER: &str = "nanodns";
    const BIN_DIR: &str = "/usr/local/bin";
    const CONFIG_DIR: &str = "/etc/nanodns";
    const DATA_DIR: &str = "/var/lib/nanodns";
    const UNIT_DIR: &str = "/etc/systemd/system";

    fn unit_path() -> PathBuf {
        Path::new(UNIT_DIR).join("nano-dns.service")
    }

    fn run<I, S>(program: &str, args: I) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|error| Error::Service(format!("cannot execute {program}: {error}")))?;
        if !status.success() {
            return Err(Error::Service(format!(
                "{program} failed with status {status}"
            )));
        }
        Ok(status)
    }

    fn succeeds<I, S>(program: &str, args: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(program)
            .args(args)
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Copy the source `data` directory so relative paths in the JSON keep working.
    fn copy_data(config_source: &Path) -> Result<()> {
        let parent = config_source.parent().unwrap_or_else(|| Path::new("."));
        let source = parent.join("data");
        if !source.is_dir() {
            return Ok(());
        }
        copy_dir(&source, &Path::new(DATA_DIR).join("data"))
    }

    fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
        fs::create_dir_all(destination).map_err(|error| {
            Error::Service(format!("cannot create {}: {error}", destination.display()))
        })?;
        for entry in fs::read_dir(source)
            .map_err(|error| Error::Service(format!("cannot read {}: {error}", source.display())))?
        {
            let entry = entry.map_err(|error| {
                Error::Service(format!(
                    "cannot read an entry of {}: {error}",
                    source.display()
                ))
            })?;
            let target = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                Error::Service(format!(
                    "cannot inspect {}: {error}",
                    entry.path().display()
                ))
            })?;
            if metadata.is_dir() {
                copy_dir(&entry.path(), &target)?;
            } else if metadata.is_file() {
                fs::copy(entry.path(), &target).map_err(|error| {
                    Error::Service(format!("cannot copy {}: {error}", entry.path().display()))
                })?;
            }
        }
        Ok(())
    }

    fn require_root() -> Result<()> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| Error::Service(format!("cannot read /proc/self/status: {error}")))?;
        let effective_uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u32>().ok());
        if effective_uid != Some(0) {
            return Err(Error::Service(
                "this command must run as root; use sudo nano-dns install-service".to_owned(),
            ));
        }
        Ok(())
    }

    /// Quote a path for use in a systemd `ExecStart` line.
    fn quote(value: &Path) -> String {
        let text = value.to_string_lossy();
        let mut quoted = String::with_capacity(text.len() + 2);
        quoted.push('"');
        for character in text.chars() {
            match character {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                _ => quoted.push(character),
            }
        }
        quoted.push('"');
        quoted
    }

    /// Build the systemd unit for the given absolute executable and config paths.
    fn unit_file(executable: &Path, config: &Path) -> String {
        format!(
            "[Unit]\n\
             Description={} DNS server\n\
             Documentation=https://github.com/codigominimo/NanoDNS\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             User={USER}\n\
             Group={USER}\n\
             ExecStart={} --config {}\n\
             WorkingDirectory={DATA_DIR}\n\
             Restart=on-failure\n\
             RestartSec=5s\n\
             TimeoutStopSec=20s\n\
             AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
             CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
             NoNewPrivileges=yes\n\
             ProtectSystem=strict\n\
             ProtectHome=yes\n\
             ReadWritePaths={DATA_DIR}\n\
             PrivateTmp=yes\n\
             PrivateDevices=yes\n\
             ProtectKernelTunables=yes\n\
             ProtectKernelModules=yes\n\
             ProtectControlGroups=yes\n\
             RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\
             LockPersonality=yes\n\
             MemoryDenyWriteExecute=yes\n\
             RestrictRealtime=yes\n\
             UMask=0077\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            super::SERVICE_NAME,
            quote(executable),
            quote(config)
        )
    }

    /// Install the binary, configuration and systemd unit, then enable the service.
    pub fn install(config: &Path) -> Result<()> {
        require_root()?;
        let config_source = config.canonicalize().map_err(|error| {
            Error::Service(format!("cannot resolve {}: {error}", config.display()))
        })?;
        let executable = std::env::current_exe()
            .map_err(|error| Error::Service(format!("cannot find current executable: {error}")))?;

        if !succeeds("id", ["-u", USER]) {
            run(
                "useradd",
                [
                    "--system",
                    "--user-group",
                    "--home-dir",
                    DATA_DIR,
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    USER,
                ],
            )?;
        }
        fs::create_dir_all(CONFIG_DIR)
            .map_err(|error| Error::Service(format!("cannot create {CONFIG_DIR}: {error}")))?;
        fs::create_dir_all(DATA_DIR)
            .map_err(|error| Error::Service(format!("cannot create {DATA_DIR}: {error}")))?;

        let binary = Path::new(BIN_DIR).join("nano-dns");
        fs::copy(&executable, &binary).map_err(|error| {
            Error::Service(format!("cannot install {}: {error}", binary.display()))
        })?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).map_err(|error| {
            Error::Service(format!(
                "cannot set permissions on {}: {error}",
                binary.display()
            ))
        })?;

        let config_target = Path::new(CONFIG_DIR).join("nano-dns.json");
        if !config_target.exists() {
            fs::copy(&config_source, &config_target).map_err(|error| {
                Error::Service(format!(
                    "cannot copy configuration to {}: {error}",
                    config_target.display()
                ))
            })?;
        }
        fs::set_permissions(&config_target, fs::Permissions::from_mode(0o640)).map_err(
            |error| {
                Error::Service(format!(
                    "cannot set permissions on {}: {error}",
                    config_target.display()
                ))
            },
        )?;
        copy_data(&config_source)?;
        run(
            "chown",
            [OsStr::new("root:nanodns"), config_target.as_os_str()],
        )?;
        run(
            "chown",
            [
                OsStr::new("-R"),
                OsStr::new("nanodns:nanodns"),
                OsStr::new(DATA_DIR),
            ],
        )?;

        fs::write(unit_path(), unit_file(&binary, &config_target)).map_err(|error| {
            Error::Service(format!("cannot write {}: {error}", unit_path().display()))
        })?;
        fs::set_permissions(unit_path(), fs::Permissions::from_mode(0o644)).map_err(|error| {
            Error::Service(format!(
                "cannot set permissions on {}: {error}",
                unit_path().display()
            ))
        })?;

        run("systemctl", ["daemon-reload"])?;
        run("systemctl", ["enable", "nano-dns.service"])?;
        println!(
            "NanoDNS installed. Edit {} if needed, then run: \
             sudo systemctl start nano-dns",
            config_target.display()
        );
        Ok(())
    }

    /// Disable and remove the systemd unit. `--purge` also removes config and data.
    pub fn uninstall(purge: bool) -> Result<()> {
        require_root()?;
        let _ = run("systemctl", ["stop", "nano-dns.service"]);
        let _ = run("systemctl", ["disable", "nano-dns.service"]);
        if unit_path().exists() {
            fs::remove_file(unit_path()).map_err(|error| {
                Error::Service(format!("cannot remove {}: {error}", unit_path().display()))
            })?;
        }
        run("systemctl", ["daemon-reload"])?;
        if purge {
            for directory in [CONFIG_DIR, DATA_DIR] {
                if Path::new(directory).exists() {
                    fs::remove_dir_all(directory).map_err(|error| {
                        Error::Service(format!("cannot remove {directory}: {error}"))
                    })?;
                }
            }
        }
        println!("NanoDNS service removed.");
        Ok(())
    }

    /// Start the systemd service.
    pub fn start() -> Result<()> {
        require_root()?;
        run("systemctl", ["start", "nano-dns.service"])?;
        println!("NanoDNS service started.");
        Ok(())
    }

    /// Stop the systemd service.
    pub fn stop() -> Result<()> {
        require_root()?;
        run("systemctl", ["stop", "nano-dns.service"])?;
        println!("NanoDNS service stopped.");
        Ok(())
    }

    /// Show the systemd service status.
    pub fn status() -> Result<()> {
        let status = Command::new("systemctl")
            .args(["status", "nano-dns.service", "--no-pager"])
            .status()
            .map_err(|error| Error::Service(format!("cannot execute systemctl: {error}")))?;
        if !status.success() {
            return Err(Error::Service(
                "NanoDNS is not active or not installed; see the systemctl output above".to_owned(),
            ));
        }
        Ok(())
    }

    /// Print the generated unit file without installing anything.
    pub fn print_unit(config: &Path) -> Result<()> {
        let config = config.canonicalize().map_err(|error| {
            Error::Service(format!("cannot resolve {}: {error}", config.display()))
        })?;
        let executable = std::env::current_exe()
            .map_err(|error| Error::Service(format!("cannot find current executable: {error}")))?;
        print!("{}", unit_file(&executable, &config));
        Ok(())
    }

    /// Service mode is owned by systemd on Unix; the process just runs in console mode.
    pub fn run_service_mode(_config: &Path) -> Result<()> {
        Err(Error::Service(
            "the internal --service flag is only valid on Windows".to_owned(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unit_file_uses_the_dedicated_user_and_absolute_paths() {
            let unit = unit_file(
                Path::new("/usr/local/bin/nano-dns"),
                Path::new("/etc/nanodns/nano-dns.json"),
            );
            assert!(unit.contains("User=nanodns"));
            assert!(unit.contains("Group=nanodns"));
            assert!(unit.contains(
                "ExecStart=\"/usr/local/bin/nano-dns\" --config \"/etc/nanodns/nano-dns.json\""
            ));
            assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
            assert!(unit.contains("ReadWritePaths=/var/lib/nanodns"));
        }

        #[test]
        fn unit_file_quotes_backslashes_and_double_quotes() {
            let unit = unit_file(
                Path::new("/opt/my\\dns"),
                Path::new("/etc/dns \"local\".json"),
            );
            assert!(unit.contains("/opt/my\\\\dns"));
            assert!(unit.contains("/etc/dns \\\"local\\\".json"));
        }

        #[test]
        fn effective_uid_is_read_from_proc_status() {
            let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
            let uid = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|value| value.split_whitespace().nth(1));
            assert!(
                uid.is_some(),
                "the test host should expose /proc/self/status"
            );
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use nano_dns_core::config::{self, DEFAULT_CONFIG_FILE};
    use nano_dns_core::error::{Error, Result};
    use nano_dns_core::runtime;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceSidType, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const DISPLAY_NAME: &str = "NanoDNS DNS Server";
    const DESCRIPTION: &str = "Minimal, modular DNS server with optional filtering and DoH/DoT";
    const ACCOUNT: &str = "NT SERVICE\\NanoDNS";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const START_TIMEOUT: Duration = Duration::from_secs(15);

    static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    fn win_error(context: &str, error: windows_service::Error) -> Error {
        let detail = match &error {
            windows_service::Error::Winapi(io_error) => io_error.to_string(),
            _ => error.to_string(),
        };
        Error::Service(format!("{context}: {detail}"))
    }

    fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, access).map_err(|error| {
            win_error(
                "cannot connect to the Windows service manager (run as Administrator)",
                error,
            )
        })
    }

    fn open_service(access: ServiceAccess) -> Result<windows_service::service::Service> {
        manager(ServiceManagerAccess::CONNECT)?
            .open_service(super::SERVICE_NAME, access)
            .map_err(|error| win_error("cannot open the NanoDNS service", error))
    }

    fn run<I, S>(program: &str, args: I) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|error| Error::Service(format!("cannot execute {program}: {error}")))?;
        if !status.success() {
            return Err(Error::Service(format!(
                "{program} failed with status {status}"
            )));
        }
        Ok(status)
    }

    fn data_dir() -> PathBuf {
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        program_data.join("NanoDNS")
    }

    fn grant_access(directory: &Path) -> Result<()> {
        run(
            "icacls",
            [
                directory.as_os_str(),
                OsStr::new("/grant"),
                OsStr::new("NT SERVICE\\NanoDNS:(OI)(CI)M"),
                OsStr::new("/T"),
            ],
        )?;
        Ok(())
    }

    fn absolute(path: &Path) -> Result<PathBuf> {
        path.canonicalize()
            .map_err(|error| Error::Service(format!("cannot resolve {}: {error}", path.display())))
    }

    /// Copy the source `data` directory so relative paths in the JSON keep working.
    fn copy_data(config_source: &Path, directory: &Path) -> Result<()> {
        let parent = config_source.parent().unwrap_or_else(|| Path::new("."));
        let source = parent.join("data");
        if !source.is_dir() {
            return Ok(());
        }
        copy_dir(&source, &directory.join("data"))
    }

    fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
        fs::create_dir_all(destination).map_err(|error| {
            Error::Service(format!("cannot create {}: {error}", destination.display()))
        })?;
        for entry in fs::read_dir(source)
            .map_err(|error| Error::Service(format!("cannot read {}: {error}", source.display())))?
        {
            let entry = entry.map_err(|error| {
                Error::Service(format!(
                    "cannot read an entry of {}: {error}",
                    source.display()
                ))
            })?;
            let target = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                Error::Service(format!(
                    "cannot inspect {}: {error}",
                    entry.path().display()
                ))
            })?;
            if metadata.is_dir() {
                copy_dir(&entry.path(), &target)?;
            } else if metadata.is_file() {
                fs::copy(entry.path(), &target).map_err(|error| {
                    Error::Service(format!("cannot copy {}: {error}", entry.path().display()))
                })?;
            }
        }
        Ok(())
    }

    /// Describe the SCM registration for the installed executable and config.
    fn service_info(binary: PathBuf, config: PathBuf) -> ServiceInfo {
        ServiceInfo {
            name: OsString::from(super::SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: binary,
            launch_arguments: vec![
                OsString::from("--service"),
                OsString::from("--config"),
                config.into_os_string(),
            ],
            dependencies: Vec::new(),
            account_name: Some(OsString::from(ACCOUNT)),
            account_password: None,
        }
    }

    /// Copy the executable and configuration under ProgramData and register the service.
    pub fn install(config: &Path) -> Result<()> {
        let config_source = absolute(config)?;
        let executable = std::env::current_exe()
            .map_err(|error| Error::Service(format!("cannot find current executable: {error}")))?;
        let directory = data_dir();
        fs::create_dir_all(&directory).map_err(|error| {
            Error::Service(format!("cannot create {}: {error}", directory.display()))
        })?;

        if open_service(ServiceAccess::QUERY_STATUS).is_ok() {
            return Err(Error::Service(
                "NanoDNS is already installed; run nano-dns uninstall-service first".to_owned(),
            ));
        }

        let binary = directory.join("nano-dns.exe");
        let config_target = directory.join("nano-dns.json");
        fs::copy(&executable, &binary).map_err(|error| {
            Error::Service(format!(
                "cannot copy the executable to {}: {error} (stop the service first if upgrading)",
                binary.display()
            ))
        })?;
        if !config_target.exists() {
            fs::copy(&config_source, &config_target).map_err(|error| {
                Error::Service(format!(
                    "cannot copy the configuration to {}: {error}",
                    config_target.display()
                ))
            })?;
        }
        copy_data(&config_source, &directory)?;
        grant_access(&directory)?;

        let service_manager =
            manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let info = service_info(binary, config_target.clone());
        let access = ServiceAccess::QUERY_CONFIG
            | ServiceAccess::QUERY_STATUS
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::DELETE;
        let service = service_manager
            .create_service(&info, access)
            .map_err(|error| win_error("cannot create the NanoDNS service", error))?;
        service
            .set_description(DESCRIPTION)
            .map_err(|error| win_error("cannot set the service description", error))?;
        service
            .set_config_service_sid_info(ServiceSidType::Unrestricted)
            .map_err(|error| win_error("cannot configure the service SID", error))?;
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                }]),
            })
            .map_err(|error| win_error("cannot configure service recovery", error))?;

        println!(
            "NanoDNS installed as {} using the virtual account {ACCOUNT}. \
             Edit {} if needed, then run nano-dns start.",
            super::SERVICE_NAME,
            config_target.display()
        );
        Ok(())
    }

    /// Stop, delete and optionally remove `%ProgramData%\NanoDNS`.
    pub fn uninstall(purge: bool) -> Result<()> {
        let service = open_service(
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )?;
        if service
            .query_status()
            .map_err(|error| win_error("cannot query service status", error))?
            .current_state
            != ServiceState::Stopped
        {
            service
                .stop()
                .map_err(|error| win_error("cannot stop the service", error))?;
        }
        service
            .delete()
            .map_err(|error| win_error("cannot delete the service", error))?;
        drop(service);
        if purge {
            fs::remove_dir_all(data_dir()).map_err(|error| {
                Error::Service(format!("cannot remove the NanoDNS data directory: {error}"))
            })?;
        }
        println!("NanoDNS service removed.");
        Ok(())
    }

    /// Start the registered service.
    pub fn start() -> Result<()> {
        let service = open_service(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        service
            .start::<&OsStr>(&[])
            .map_err(|error| win_error("cannot start the service", error))?;
        println!("NanoDNS service started.");
        Ok(())
    }

    /// Stop the registered service.
    pub fn stop() -> Result<()> {
        let service = open_service(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        service
            .stop()
            .map_err(|error| win_error("cannot stop the service", error))?;
        println!("NanoDNS service stopped.");
        Ok(())
    }

    /// Print the current SCM service state.
    pub fn status() -> Result<()> {
        let service = open_service(ServiceAccess::QUERY_STATUS)?;
        let status = service
            .query_status()
            .map_err(|error| win_error("cannot query service status", error))?;
        println!(
            "{}: {:?} (exit code {:?})",
            super::SERVICE_NAME,
            status.current_state,
            status.exit_code
        );
        Ok(())
    }

    /// Enter the service control dispatcher. Called only for the hidden `--service` flag.
    pub fn run_service_mode(config: &Path) -> Result<()> {
        let absolute = absolute(config)?;
        CONFIG_PATH
            .set(absolute)
            .map_err(|_| Error::Service("service mode initialized twice".to_owned()))?;
        service_dispatcher::start(super::SERVICE_NAME, ffi_service_main)
            .map_err(|error| win_error("cannot start the service dispatcher", error))
    }

    fn append_log(path: &Path, message: &str) {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{message}");
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let config_path = CONFIG_PATH
            .get()
            .cloned()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE));
        let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        let log_path = parent.join("nano-dns.log");
        if let Err(error) = std::env::set_current_dir(parent) {
            append_log(&log_path, &format!("cannot set working directory: {error}"));
            return;
        }

        let config = match config::load(&config_path) {
            Ok(config) => config,
            Err(error) => {
                append_log(&log_path, &format!("cannot load configuration: {error}"));
                return;
            }
        };
        let _tracing = match runtime::install_with_log_file(&config, &log_path) {
            Ok(guard) => Some(guard),
            Err(error) => {
                append_log(&log_path, &format!("cannot open log file: {error}"));
                None
            }
        };

        if let Err(error) = run_service(&config) {
            tracing::error!(%error, "NanoDNS service failed");
            append_log(&log_path, &format!("service error: {error}"));
        }
    }

    fn service_status(
        state: ServiceState,
        controls: ServiceControlAccept,
        exit_code: u32,
        checkpoint: u32,
        wait_hint: Duration,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint,
            wait_hint,
            process_id: None,
        }
    }

    fn run_service(config: &config::Config) -> windows_service::Result<()> {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stop_tx = Mutex::new(Some(stop_tx));
        let status_handle =
            service_control_handler::register(super::SERVICE_NAME, move |control| match control {
                ServiceControl::Stop => {
                    if let Some(sender) = stop_tx.lock().ok().and_then(|mut guard| guard.take()) {
                        let _ = sender.send(());
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        status_handle.set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            0,
            1,
            START_TIMEOUT,
        ))?;
        status_handle.set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP,
            0,
            0,
            Duration::ZERO,
        ))?;
        let pending_handle = status_handle;
        let shutdown = async move {
            let _ = stop_rx.await;
            let _ = pending_handle.set_service_status(service_status(
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                0,
                1,
                START_TIMEOUT,
            ));
        };

        let result = runtime::run(crate::run_servers(config.clone(), shutdown));
        let exit_code = if result.is_ok() { 0 } else { 1 };
        status_handle.set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
            0,
            Duration::ZERO,
        ))?;
        result.map_err(|error| {
            windows_service::Error::Winapi(std::io::Error::other(error.to_string()))
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn service_info_uses_the_virtual_account_and_absolute_config() {
            let info = service_info(
                PathBuf::from(r"C:\ProgramData\NanoDNS\nano-dns.exe"),
                PathBuf::from(r"C:\ProgramData\NanoDNS\nano-dns.json"),
            );
            assert_eq!(info.name, OsString::from("NanoDNS"));
            assert_eq!(info.display_name, OsString::from(DISPLAY_NAME));
            assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
            assert_eq!(info.start_type, ServiceStartType::AutoStart);
            assert_eq!(info.account_name, Some(OsString::from(ACCOUNT)));
            assert_eq!(info.account_password, None);
            assert_eq!(
                info.launch_arguments,
                vec![
                    OsString::from("--service"),
                    OsString::from("--config"),
                    OsString::from(r"C:\ProgramData\NanoDNS\nano-dns.json"),
                ]
            );
        }

        #[test]
        fn win_error_includes_the_underlying_io_message() {
            let error = win_error(
                "cannot open the NanoDNS service",
                windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5)),
            );
            let message = error.to_string();
            assert!(message.starts_with("service error: cannot open the NanoDNS service: "));
            assert!(!message.ends_with(": "));
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn run_service_mode(_config: &std::path::Path) -> nano_dns_core::error::Result<()> {
    Err(nano_dns_core::error::Error::Service(
        "service installation is only supported on Windows and Linux".to_owned(),
    ))
}
