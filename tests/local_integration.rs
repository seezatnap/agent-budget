use std::env;
use std::process::Command;

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

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim_start().starts_with('[') && stdout.trim_end().ends_with(']'),
        "expected JSON array output, got: {stdout}"
    );

    assert_eq!(
        stdout.matches("\"model\":\"").count(),
        2,
        "expected exactly two model entries"
    );
    assert!(stdout.contains("\"model\":\"codex\""));
    assert!(stdout.contains("\"model\":\"claude\""));

    let weekly_values = extract_values_for_key(&stdout, "weeklyLimit");
    assert_eq!(
        weekly_values.len(),
        2,
        "expected two weeklyLimit values, got: {stdout}"
    );

    for weekly_limit in weekly_values {
        assert!(
            weekly_limit == "??" || looks_like_percentage(&weekly_limit),
            "unexpected weeklyLimit value: {weekly_limit}"
        );
    }

    let short_term_values = extract_values_for_key(&stdout, "shortTermLimit");
    assert_eq!(
        short_term_values.len(),
        2,
        "expected two shortTermLimit values, got: {stdout}"
    );

    for short_term_limit in short_term_values {
        assert!(
            short_term_limit == "??" || looks_like_percentage(&short_term_limit),
            "unexpected shortTermLimit value: {short_term_limit}"
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

fn extract_values_for_key(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\":\"");
    let mut values = Vec::new();
    let mut cursor = json;

    while let Some(start) = cursor.find(&needle) {
        let remaining = &cursor[start + needle.len()..];
        let Some(end) = remaining.find('"') else {
            break;
        };

        values.push(remaining[..end].to_string());
        cursor = &remaining[end + 1..];
    }

    values
}
