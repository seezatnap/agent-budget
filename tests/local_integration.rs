use serde::Deserialize;
use std::env;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct BudgetRow {
    model: String,
    #[serde(rename = "weeklyRemaining")]
    weekly_remaining: String,
}

#[test]
fn local_dependencies_are_installed() {
    if env::var_os("CI").is_some() {
        return;
    }

    for binary in ["codex", "claude", "tmux"] {
        assert!(
            command_exists(binary),
            "expected `{binary}` to be installed and on PATH"
        );
    }
}

#[test]
fn help_output_is_available() {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-budget"))
        .arg("--help")
        .output()
        .expect("run --help");

    assert!(output.status.success(), "help command failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("agent-budget [--json]"));
}

#[test]
#[ignore = "Runs live codex/claude sessions in tmux; execute locally when you want full e2e verification."]
fn live_json_output_matches_contract() {
    for binary in ["codex", "claude", "tmux"] {
        assert!(
            command_exists(binary),
            "expected `{binary}` to be installed and on PATH"
        );
    }

    let output = Command::new(env!("CARGO_BIN_EXE_agent-budget"))
        .arg("--json")
        .output()
        .expect("run --json");

    assert!(
        output.status.success(),
        "agent-budget failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rows: Vec<BudgetRow> = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_eq!(rows.len(), 2, "expected codex + claude entries");

    assert!(rows.iter().any(|r| r.model == "codex"));
    assert!(rows.iter().any(|r| r.model == "claude"));

    for row in rows {
        assert!(
            row.weekly_remaining == "??" || looks_like_percentage(&row.weekly_remaining),
            "unexpected weeklyRemaining for {}: {}",
            row.model,
            row.weekly_remaining
        );
    }
}

fn command_exists(binary: &str) -> bool {
    Command::new("bash")
        .arg("-lc")
        .arg(format!("command -v {binary} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn looks_like_percentage(value: &str) -> bool {
    let Some(number) = value.strip_suffix('%') else {
        return false;
    };

    if number.is_empty() || !number.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    number.parse::<u8>().map(|n| n <= 100).unwrap_or(false)
}
