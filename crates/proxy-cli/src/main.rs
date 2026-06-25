use proxy_core::daemon_recover;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use proxy_core::local_socks;
use proxy_core::proxy_url::socks5_url;
use proxy_core::secret::{read_password_from_file, read_password_from_stdin};
use proxy_core::socks5;
use proxy_core::system_proxy;
use proxy_core::tun::tun2proxy_args;
use proxy_core::tun_runner;
use proxy_core::{
    AppConfig, ConfigError, CredentialEntry, ProxyEndpoint, ProxyProfile, ResolvedProfile,
    RoutingMode, StoredProxyTarget, StructuredProxyTarget,
};
use std::env;
use std::path::PathBuf;
use std::process::Child;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    init_logging();
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_env("SOCKS5PROXY_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn run() -> anyhow::Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let command = args
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{}", usage("missing command")))?;
    args.remove(0);

    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "config-path" => {
            println!("{}", AppConfig::config_path()?.display());
            Ok(())
        }
        "show" => show_config(),
        "profiles" => list_profiles(),
        "activate" => activate_profile(&args),
        "save" => save_profile(&args),
        "recover" => {
            daemon_recover()?;
            println!("recovered.");
            Ok(())
        }
        "test" => {
            let profile = resolve_profile_for_action(&args)?;
            socks5::handshake(&profile.endpoint).map_err(|e| anyhow::anyhow!(e))?;
            println!("SOCKS5 handshake succeeded.");
            Ok(())
        }
        "url" => {
            let profile = resolve_profile_for_action(&args)?;
            println!("{}", socks5_url(&profile.endpoint));
            Ok(())
        }
        "tun-args" => {
            let profile = resolve_profile_for_action(&args)?;
            println!("{}", shell_join(&tun2proxy_args(&profile)));
            Ok(())
        }
        "start" => {
            let profile = resolve_profile_for_action(&args)?;
            start(profile)
        }
        other => Err(anyhow::anyhow!(
            "{}",
            usage(&format!("unknown command '{other}'"))
        )),
    }
}

fn show_config() -> anyhow::Result<()> {
    let config = load_config()?;
    print!("{}", config.to_toml()?);
    let active = config.resolve_profile_by_selector(config.active_profile_id.as_deref())?;
    let selected = config.selected_profile()?;
    println!(
        "\n# Enabled: {}\n# Active profile: {} ({})\n# Selected profile: {} ({})\n# Selected proxy: {}",
        config.enabled,
        active.name,
        active.id,
        selected.name,
        selected.id,
        socks5_url(&active.endpoint)
    );
    Ok(())
}

fn list_profiles() -> anyhow::Result<()> {
    let config = load_config()?;
    let active = config
        .active_profile_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("active profile is not configured"))?;
    let selected = config.selected_profile_id.clone();

    for profile in &config.profiles {
        let marker = if profile.id == active {
            "*"
        } else if Some(profile.id.clone()) == selected {
            ">"
        } else {
            " "
        };
        println!("{marker} {} ({})", profile.name, profile.id);
    }

    Ok(())
}

fn activate_profile(args: &[String]) -> anyhow::Result<()> {
    let selector = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("{}", usage("activate requires a profile id or name")))?;

    let mut config = load_config()?;
    let profile = config.profile_by_selector(selector)?.clone();
    config.selected_profile_id = Some(profile.id.clone());
    config.active_profile_id = Some(profile.id.clone());
    let path = config.save_default_path()?;
    println!(
        "activated {} ({}) in {}",
        profile.name,
        profile.id,
        path.display()
    );
    Ok(())
}

fn save_profile(args: &[String]) -> anyhow::Result<()> {
    let options = save_options_from_args(args)?;
    let mut config = load_config_or_default();

    let target_index = if let Some(selector) = options.selector.as_deref() {
        config
            .profiles
            .iter()
            .position(|profile| profile.id == selector || profile.name == selector)
    } else {
        config.active_profile_id.as_ref().and_then(|active| {
            config
                .profiles
                .iter()
                .position(|profile| &profile.id == active)
        })
    };

    let mut profile = target_index
        .and_then(|index| config.profiles.get(index).cloned())
        .unwrap_or_else(|| {
            ProxyProfile::default_named(
                options
                    .name
                    .clone()
                    .unwrap_or_else(|| "New Profile".to_string()),
            )
        });

    if target_index.is_none() {
        profile.id = generate_profile_id();
    }
    profile.name = options.name.clone().unwrap_or_else(|| profile.name.clone());
    profile.routing_mode = options.routing_mode;
    profile.proxy_dns = options.proxy_dns;
    profile.bypass = options.bypass.clone();
    profile.target = StoredProxyTarget::Structured(StructuredProxyTarget {
        host: options.endpoint.host.clone(),
        port: options.endpoint.port,
        credentials: match (&options.endpoint.username, &options.endpoint.password) {
            (Some(username), Some(password)) => vec![CredentialEntry {
                id: "cred-inline".to_string(),
                label: "Credential 1".to_string(),
                username: username.clone(),
                password: password.clone(),
            }],
            _ => Vec::new(),
        },
        selected_credential_id: if options.endpoint.username.is_some()
            && options.endpoint.password.is_some()
        {
            Some("cred-inline".to_string())
        } else {
            None
        },
    });

    match target_index {
        Some(index) => config.profiles[index] = profile,
        None => config.profiles.push(profile),
    }

    if let Some(index) = target_index {
        config.selected_profile_id = Some(config.profiles[index].id.clone());
        config.active_profile_id = Some(config.profiles[index].id.clone());
    } else if let Some(profile) = config.profiles.last() {
        config.selected_profile_id = Some(profile.id.clone());
        config.active_profile_id = Some(profile.id.clone());
    }

    let path = config.save_default_path()?;
    println!("saved {}", path.display());
    Ok(())
}

fn start(profile: ResolvedProfile) -> anyhow::Result<()> {
    match profile.routing_mode {
        RoutingMode::System => {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let local_server = Some(local_socks::start(profile.endpoint.clone()).map_err(
                |error| {
                    anyhow::anyhow!("failed to start local system-proxy SOCKS5 adapter: {error}")
                },
            )?);
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            let local_server: Option<proxy_core::LocalSocksServer> = None;

            let snapshot = system_proxy::enable(&profile)?;
            println!(
                "system proxy enabled for '{}'. Press Enter to restore and exit.",
                profile.name
            );
            wait_for_enter();
            system_proxy::restore(snapshot)?;
            if let Some(server) = local_server {
                server.shutdown().map_err(|error| {
                    anyhow::anyhow!("failed to stop local SOCKS5 adapter: {error}")
                })?;
            }
            println!("system proxy restored.");
            Ok(())
        }
        RoutingMode::Tun => {
            let mut child = tun_runner::spawn(&profile)?;
            println!(
                "tun2proxy started for '{}' with pid {}. Press Enter to stop.",
                profile.name,
                child.id()
            );
            wait_for_enter();
            stop_child(&mut child);
            println!("tun2proxy stopped.");
            Ok(())
        }
    }
}

fn wait_for_enter() {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn resolve_profile_for_action(args: &[String]) -> anyhow::Result<ResolvedProfile> {
    if args.is_empty() {
        return Ok(load_config()?.resolve_profile_by_selector(None)?);
    }

    if args[0].starts_with("--") {
        return profile_from_inline_args(args);
    }

    if args.len() > 1 {
        anyhow::bail!(usage(
            "profile selectors cannot be combined with inline options for this command",
        ));
    }

    Ok(load_config()?.resolve_profile_by_selector(Some(&args[0]))?)
}

fn profile_from_inline_args(args: &[String]) -> anyhow::Result<ResolvedProfile> {
    let options = save_options_from_args(args)?;
    Ok(ResolvedProfile {
        id: "inline".to_string(),
        name: options.name.unwrap_or_else(|| "Inline".to_string()),
        endpoint: options.endpoint,
        routing_mode: options.routing_mode,
        proxy_dns: options.proxy_dns,
        startup_cleanup_enabled: true,
        bypass: options.bypass,
    })
}

fn load_config() -> anyhow::Result<AppConfig> {
    Ok(AppConfig::load_default_path()?)
}

fn load_config_or_default() -> AppConfig {
    AppConfig::load_default_path().unwrap_or_default()
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "-_./:=@".contains(ch))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_usage() {
    println!("{}", usage_text());
}

fn usage(message: &str) -> String {
    if message.is_empty() {
        usage_text()
    } else {
        format!("{message}\n\n{}", usage_text())
    }
}

fn usage_text() -> String {
    concat!(
        "Usage:\n",
        "  socks5proxy config-path\n",
        "  socks5proxy show\n",
        "  socks5proxy profiles\n",
        "  socks5proxy activate PROFILE\n",
        "  socks5proxy recover\n",
        "  socks5proxy save [--profile PROFILE] [--name NAME] --host HOST [--port PORT]\n",
        "                   [--username USER (--password PASS | --password-stdin | --password-file PATH)]\n",
        "                   [--routing-mode system|tun] [--proxy-dns|--no-proxy-dns] [--bypass ROUTE]\n",
        "  socks5proxy test [PROFILE|options]\n",
        "  socks5proxy url [PROFILE|options]\n",
        "  socks5proxy tun-args [PROFILE|options]\n",
        "  socks5proxy start [PROFILE|options]\n\n",
        "Prefer --password-stdin or --password-file PATH over --password (which leaks via `ps`/shell history).\n",
        "When options are omitted for test/url/tun-args/start, the active saved profile is used.\n",
        "Passwords are stored in plain text in the config file (file is created with mode 0600 on Unix).\n"
    )
    .to_string()
}

struct SaveOptions {
    selector: Option<String>,
    name: Option<String>,
    endpoint: ProxyEndpoint,
    routing_mode: RoutingMode,
    proxy_dns: bool,
    bypass: Vec<String>,
}

fn save_options_from_args(args: &[String]) -> anyhow::Result<SaveOptions> {
    let mut endpoint = ProxyEndpoint {
        host: String::new(),
        port: 1080,
        username: None,
        password: None,
    };
    let mut selector = None;
    let mut name = None;
    let mut routing_mode = RoutingMode::System;
    let mut proxy_dns = true;
    let mut bypass = Vec::new();
    let mut seen_host = false;
    let mut index = 0;
    let mut password_source: Option<&'static str> = None;

    let set_password = |value: String,
                        source: &'static str,
                        current: &mut Option<&'static str>,
                        endpoint: &mut ProxyEndpoint|
     -> anyhow::Result<()> {
        if let Some(existing) = *current {
            anyhow::bail!(
                "conflicting password sources: --{existing} was already provided, cannot combine with --{source}"
            );
        }
        endpoint.password = Some(value);
        *current = Some(source);
        Ok(())
    };

    while index < args.len() {
        match args[index].as_str() {
            "--profile" => selector = Some(take_value(args, &mut index, "--profile")?),
            "--name" => name = Some(take_value(args, &mut index, "--name")?),
            "--host" => {
                endpoint.host = take_value(args, &mut index, "--host")?;
                seen_host = true;
            }
            "--port" => {
                endpoint.port = take_value(args, &mut index, "--port")?
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("port must be between 1 and 65535"))?;
            }
            "--username" => endpoint.username = Some(take_value(args, &mut index, "--username")?),
            "--password" => {
                let value = take_value(args, &mut index, "--password")?;
                set_password(value, "password", &mut password_source, &mut endpoint)?;
            }
            "--password-stdin" => {
                let value = read_password_from_stdin()?;
                set_password(value, "password-stdin", &mut password_source, &mut endpoint)?;
            }
            "--password-file" => {
                let path = PathBuf::from(take_value(args, &mut index, "--password-file")?);
                let value = read_password_from_file(&path)?;
                set_password(value, "password-file", &mut password_source, &mut endpoint)?;
            }
            "--routing-mode" => {
                routing_mode = take_value(args, &mut index, "--routing-mode")?
                    .parse::<RoutingMode>()
                    .map_err(|error: ConfigError| anyhow::anyhow!(error.to_string()))?;
            }
            "--proxy-dns" => proxy_dns = true,
            "--no-proxy-dns" => proxy_dns = false,
            "--bypass" => bypass.push(take_value(args, &mut index, "--bypass")?),
            "--help" | "-h" => anyhow::bail!(usage("")),
            other => anyhow::bail!(usage(&format!("unknown option '{other}'"))),
        }
        index += 1;
    }

    if !seen_host {
        anyhow::bail!(usage("--host is required"));
    }

    if endpoint.host.trim().is_empty() {
        anyhow::bail!("host must not be empty");
    }
    if endpoint.password.is_some() && endpoint.username.is_none() {
        anyhow::bail!("password requires a username");
    }

    Ok(SaveOptions {
        selector,
        name,
        endpoint,
        routing_mode,
        proxy_dns,
        bypass,
    })
}

fn take_value(args: &[String], index: &mut usize, flag: &str) -> anyhow::Result<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn generate_profile_id() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("profile-{stamp:x}")
}
