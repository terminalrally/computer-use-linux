use crate::{
    abs_pointer, atspi_tree, diagnostics, gnome_extension, guide, screenshot, server, windows,
};
use anyhow::{Context, Result};

pub(crate) async fn run_from_env() -> Result<()> {
    diagnostics::hydrate_session_bus_env();

    match std::env::args().nth(1).as_deref() {
        Some("mcp") => {
            let args: Vec<String> = std::env::args().skip(2).collect();
            server::serve_mcp(mcp_mode(
                &args,
                std::env::var(guide::MODE_ENV).ok().as_deref(),
            )?)
            .await
        }
        Some("guide") => server::serve_mcp(guide::ServerMode::Guide).await,
        Some("guard-accessibility") => crate::accessibility_guard::run().await,
        Some("doctor") => {
            let report = diagnostics::doctor_report();
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .context("failed to serialize doctor report")?
            );
            Ok(())
        }
        Some("setup") => {
            let report = diagnostics::setup_accessibility_report();
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .context("failed to serialize setup report")?
            );
            Ok(())
        }
        Some("apps") => {
            let apps = atspi_tree::list_accessible_apps(50).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&apps)
                    .context("failed to serialize accessible apps")?
            );
            Ok(())
        }
        Some("state") => {
            let app_name_or_bundle_identifier = std::env::args().nth(2);
            let (max_nodes, max_depth) = atspi_tree::snapshot_limits(None, None);
            let nodes = atspi_tree::snapshot_tree(
                app_name_or_bundle_identifier.as_deref(),
                None,
                max_nodes,
                max_depth,
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&nodes)
                    .context("failed to serialize accessibility tree")?
            );
            Ok(())
        }
        Some("abs-test") => {
            let x: i32 = std::env::args()
                .nth(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let y: i32 = std::env::args()
                .nth(3)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let cap = screenshot::capture_screenshot_raw().await?;
            eprintln!("desktop logical size: {}x{}", cap.width, cap.height);
            let mut p = abs_pointer::AbsPointer::create(cap.width as i32, cap.height as i32)?;
            let landing = p.click(x, y, abs_pointer::PointerButton::Left, 1)?;
            println!("{}", abs_test_report(landing, (cap.width, cap.height)));
            Ok(())
        }
        Some("screenshot") => {
            let capture = screenshot::capture_screenshot().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mime_type": capture.mime_type,
                    "source": capture.source,
                    "width": capture.width,
                    "height": capture.height,
                    "coordinate_width": capture.coordinate_width,
                    "coordinate_height": capture.coordinate_height,
                    "scale": capture.scale,
                    "resized": capture.resized,
                    "bytes": capture.bytes,
                    "original_bytes": capture.original_bytes,
                    "max_bytes": capture.max_bytes,
                    "format": capture.format,
                    "quality": capture.quality,
                    "data_url_length": capture.data_url.len()
                }))
                .context("failed to serialize screenshot report")?
            );
            Ok(())
        }
        Some("windows") => {
            let report = match windows::list_windows().await {
                Ok(windows) => {
                    let backend = windows
                        .first()
                        .map(|window| window.backend.as_str())
                        .unwrap_or(windows::GNOME_SHELL_INTROSPECT_BACKEND);
                    serde_json::json!({
                        "backend": backend,
                        "windows": windows,
                        "error": null,
                        "permissions_hint": null,
                    })
                }
                Err(error) => {
                    let error = format!("{error:#}");
                    serde_json::json!({
                        "backend": "unavailable",
                        "windows": [],
                        "error": error,
                        "permissions_hint": windows::window_permission_hint(&error),
                    })
                }
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("setup-window-targeting") => {
            let report = gnome_extension::setup_window_targeting_report().await;
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .context("failed to serialize window targeting setup report")?
            );
            Ok(())
        }
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(command) => {
            anyhow::bail!(
                "unknown command '{command}'. Expected one of: mcp, guide, doctor, setup, guard-accessibility, apps, state, screenshot, windows, setup-window-targeting"
            );
        }
        None => {
            print_help();
            Ok(())
        }
    }
}

/// Mode for `computer-use-linux mcp [--mode control|guide | --guide]`. The
/// command line wins over `COMPUTER_USE_LINUX_MODE`.
fn mcp_mode(args: &[String], env_mode: Option<&str>) -> Result<guide::ServerMode> {
    let mut mode = guide::ServerMode::parse(env_mode)
        .with_context(|| format!("invalid {}", guide::MODE_ENV))?;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--guide" => mode = guide::ServerMode::Guide,
            "--mode" => {
                let value = args
                    .next()
                    .context("--mode needs a value: control or guide")?;
                mode = guide::ServerMode::parse(Some(value))?;
            }
            other => match other.strip_prefix("--mode=") {
                Some(value) => mode = guide::ServerMode::parse(Some(value))?,
                None => anyhow::bail!(
                    "unknown mcp option '{other}'. Expected --mode control|guide or --guide"
                ),
            },
        }
    }
    Ok(mode)
}

fn abs_test_report(
    landing: abs_pointer::PointerLanding,
    dimensions: (u32, u32),
) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "requested_x": landing.requested.0,
        "requested_y": landing.requested.1,
        "x": landing.emitted.0,
        "y": landing.emitted.1,
        "w": dimensions.0,
        "h": dimensions.1
    })
}

fn print_help() {
    println!("guard-accessibility: explicit foreground accessibility hold-open; stop with Ctrl-C or SIGTERM before disabling accessibility.\n");
    println!(
        "computer-use-linux\n\nUsage:\n  computer-use-linux mcp [--mode control|guide]\n  computer-use-linux guide            (MCP server in guide mode: the agent points, you act)\n  computer-use-linux doctor\n  computer-use-linux setup\n  computer-use-linux setup-window-targeting\n  computer-use-linux apps\n  computer-use-linux state [APP_NAME]\n  computer-use-linux screenshot\n  computer-use-linux windows"
    );
}

#[cfg(test)]
mod tests {
    use super::{abs_pointer, abs_test_report, guide::ServerMode, mcp_mode};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn mcp_mode_comes_from_flags_then_environment() {
        assert_eq!(mcp_mode(&[], None).unwrap(), ServerMode::Control);
        assert_eq!(mcp_mode(&[], Some("guide")).unwrap(), ServerMode::Guide);
        assert_eq!(
            mcp_mode(&args(&["--guide"]), None).unwrap(),
            ServerMode::Guide
        );
        assert_eq!(
            mcp_mode(&args(&["--mode", "control"]), Some("guide")).unwrap(),
            ServerMode::Control
        );
        assert_eq!(
            mcp_mode(&args(&["--mode=guide"]), None).unwrap(),
            ServerMode::Guide
        );
        assert!(mcp_mode(&args(&["--mode"]), None).is_err());
        assert!(mcp_mode(&args(&["--fast"]), None).is_err());
        assert!(mcp_mode(&[], Some("drive")).is_err());
    }

    #[test]
    fn abs_test_report_distinguishes_requested_and_emitted_coordinates() {
        assert_eq!(
            abs_test_report(
                abs_pointer::PointerLanding {
                    requested: (1920, 1080),
                    emitted: (1919, 1079),
                },
                (1920, 1080)
            ),
            serde_json::json!({
                "ok": true,
                "requested_x": 1920,
                "requested_y": 1080,
                "x": 1919,
                "y": 1079,
                "w": 1920,
                "h": 1080
            })
        );
    }
}
