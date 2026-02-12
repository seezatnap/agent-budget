use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

const CODEX_SCRIPT: &str = r#"
set -euo pipefail

SESSION="codex_usage_$$"
SOCKET="/tmp/agent_budget_codex_${SESSION}.sock"
DEBUG_DIR="${AGENT_BUDGET_DEBUG_DIR:-}"
MODEL="codex"

# Start an interactive shell inside tmux and launch Codex from within it.
tmux -S "$SOCKET" new-session -d -s "$SESSION" "bash"

# Always clean up the tmux session
trap 'tmux -S "$SOCKET" kill-session -t "$SESSION" 2>/dev/null || true; rm -f "$SOCKET"' EXIT

if [ -n "$DEBUG_DIR" ]; then
  mkdir -p "$DEBUG_DIR"
  printf "%s\n" "$SOCKET" > "$DEBUG_DIR/${MODEL}_tmux_socket.txt"
fi

tmux -S "$SOCKET" send-keys -t "$SESSION" -l "codex --dangerously-bypass-approvals-and-sandbox"
tmux -S "$SOCKET" send-keys -t "$SESSION" Enter

sleep 5

# Trigger /status
if ! tmux -S "$SOCKET" has-session -t "$SESSION" 2>/dev/null; then
  echo "codex tmux session exited before usage capture" >&2
  exit 1
fi

tmux -S "$SOCKET" send-keys -t "$SESSION" -l "/status "
tmux -S "$SOCKET" send-keys -t "$SESSION" C-j
tmux -S "$SOCKET" send-keys -t "$SESSION" Enter

sleep 5

USAGE_OUTPUT="$(tmux -S "$SOCKET" capture-pane -t "$SESSION" -p -J)"
USAGE_OUTPUT_CLEAN="$(printf "%s" "$USAGE_OUTPUT" | sed -E "s/\\x1B\\[[0-9;]*[[:alpha:]]//g")"

PROMPT='Extract the remaining usage percentages for both weekly and short-term limits. Return JSON ONLY in this exact shape: {"weeklyLimit":"63%","shortTermLimit":"12%"}. Use "??" for unknown values.'
FINAL_PROMPT="$(printf "%s\n\n%s" "$PROMPT" "$USAGE_OUTPUT_CLEAN")"

if [ -n "$DEBUG_DIR" ]; then
  printf "%s" "$USAGE_OUTPUT" > "$DEBUG_DIR/${MODEL}_tmux_capture_raw.txt"
  printf "%s" "$USAGE_OUTPUT_CLEAN" > "$DEBUG_DIR/${MODEL}_tmux_capture_clean.txt"
  printf "%s" "$FINAL_PROMPT" > "$DEBUG_DIR/${MODEL}_llm_prompt.txt"
fi

RESULT="$(claude -p "$FINAL_PROMPT")"

if [ -n "$DEBUG_DIR" ]; then
  printf "%s" "$RESULT" > "$DEBUG_DIR/${MODEL}_llm_response.txt"
fi

printf "%s\n" "$RESULT"
"#;

const CLAUDE_SCRIPT: &str = r#"
set -euo pipefail

SESSION="claude_usage_$$"
SOCKET="/tmp/agent_budget_claude_${SESSION}.sock"
DEBUG_DIR="${AGENT_BUDGET_DEBUG_DIR:-}"
MODEL="claude"

# Start Claude inside tmux
tmux -S "$SOCKET" new-session -d -s "$SESSION" "bash -lc 'IS_SANDBOX=1 claude --dangerously-skip-permissions'"

# Always clean up the tmux session
trap 'tmux -S "$SOCKET" kill-session -t "$SESSION" 2>/dev/null || true; rm -f "$SOCKET"' EXIT

if [ -n "$DEBUG_DIR" ]; then
  mkdir -p "$DEBUG_DIR"
  printf "%s\n" "$SOCKET" > "$DEBUG_DIR/${MODEL}_tmux_socket.txt"
fi

sleep 5

# Trigger /usage
if ! tmux -S "$SOCKET" has-session -t "$SESSION" 2>/dev/null; then
  echo "claude tmux session exited before usage capture" >&2
  exit 1
fi

tmux -S "$SOCKET" send-keys -t "$SESSION" -l "/usage"
tmux -S "$SOCKET" send-keys -t "$SESSION" Enter
sleep 5

# Capture output
USAGE_OUTPUT="$(tmux -S "$SOCKET" capture-pane -t "$SESSION" -p -J)"

# Strip ANSI escapes (optional but helps)
USAGE_OUTPUT_CLEAN="$(printf "%s" "$USAGE_OUTPUT" | perl -pe "s/\e\[[0-9;]*[A-Za-z]//g")"

PROMPT='Extract the remaining usage percentages for both weekly and short-term limits. Return JSON ONLY in this exact shape: {"weeklyLimit":"63%","shortTermLimit":"12%"}. Use "??" for unknown values.'
FINAL_PROMPT="$(printf "%s\n\n%s" "$PROMPT" "$USAGE_OUTPUT_CLEAN")"

if [ -n "$DEBUG_DIR" ]; then
  printf "%s" "$USAGE_OUTPUT" > "$DEBUG_DIR/${MODEL}_tmux_capture_raw.txt"
  printf "%s" "$USAGE_OUTPUT_CLEAN" > "$DEBUG_DIR/${MODEL}_tmux_capture_clean.txt"
  printf "%s" "$FINAL_PROMPT" > "$DEBUG_DIR/${MODEL}_llm_prompt.txt"
fi

RESULT="$(claude -p "$FINAL_PROMPT")"

if [ -n "$DEBUG_DIR" ]; then
  printf "%s" "$RESULT" > "$DEBUG_DIR/${MODEL}_llm_response.txt"
fi

printf "%s\n" "$RESULT"
"#;

struct BudgetRow {
    model: &'static str,
    weekly_limit: String,
    short_term_limit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UsageLimits {
    weekly_limit: String,
    short_term_limit: String,
}

#[derive(Debug)]
enum OutputMode {
    Text,
    Json,
}

#[derive(Debug)]
struct CliFlags {
    mode: OutputMode,
    debug: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let flags = parse_args(env::args().skip(1))?;
    let debug_dir = if flags.debug {
        Some(create_debug_dir()?)
    } else {
        None
    };

    if let Some(dir) = &debug_dir {
        eprintln!("agent-budget debug dir: {}", dir.display());
    }

    let codex_limits = run_usage_script("codex", CODEX_SCRIPT, debug_dir.as_deref())?;
    let claude_limits = run_usage_script("claude", CLAUDE_SCRIPT, debug_dir.as_deref())?;

    let rows = [
        BudgetRow {
            model: "codex",
            weekly_limit: codex_limits.weekly_limit,
            short_term_limit: codex_limits.short_term_limit,
        },
        BudgetRow {
            model: "claude",
            weekly_limit: claude_limits.weekly_limit,
            short_term_limit: claude_limits.short_term_limit,
        },
    ];

    match flags.mode {
        OutputMode::Json => {
            let json = render_json(&rows);
            println!("{json}");
        }
        OutputMode::Text => {
            for row in rows {
                println!(
                    "{} weekly limit: {}, short-term limit: {}",
                    row.model, row.weekly_limit, row.short_term_limit
                );
            }
        }
    }

    Ok(())
}

fn parse_args<I>(args: I) -> Result<CliFlags, String>
where
    I: IntoIterator<Item = String>,
{
    let mut mode = OutputMode::Text;
    let mut debug = false;

    for arg in args {
        match arg.as_str() {
            "--json" => mode = OutputMode::Json,
            "--debug" => debug = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(CliFlags { mode, debug })
}

fn print_help() {
    println!("agent-budget");
    println!();
    println!("Usage:");
    println!("  agent-budget [--json] [--debug]");
    println!();
    println!("Options:");
    println!("  --json       Print results as JSON");
    println!("  --debug      Write debug artifacts to /tmp and print that path to stderr");
    println!("  -h, --help   Print help");
}

fn run_usage_script(
    model: &str,
    script: &str,
    debug_dir: Option<&Path>,
) -> Result<UsageLimits, String> {
    let mut command = Command::new("bash");
    command.arg("-lc").arg(script);

    if let Some(dir) = debug_dir {
        command.env("AGENT_BUDGET_DEBUG_DIR", dir);
    }

    let output = command
        .output()
        .map_err(|e| format!("failed to run bash: {e}"))?;

    if let Some(dir) = debug_dir {
        write_debug_output(dir, model, &output, script)?;
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!("usage command failed: {detail}"));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    Ok(extract_limits(&raw))
}

fn create_debug_dir() -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("failed to get system time: {e}"))?
        .as_millis();
    let pid = std::process::id();
    let dir = PathBuf::from(format!("/tmp/agent-budget-debug-{now}-{pid}"));
    fs::create_dir_all(&dir).map_err(|e| format!("failed to create debug dir {dir:?}: {e}"))?;
    Ok(dir)
}

fn write_debug_output(
    debug_dir: &Path,
    model: &str,
    output: &std::process::Output,
    script: &str,
) -> Result<(), String> {
    write_debug_file(debug_dir, model, "runner_stdout.txt", &output.stdout)?;
    write_debug_file(debug_dir, model, "runner_stderr.txt", &output.stderr)?;
    write_debug_file(debug_dir, model, "script.sh", script.as_bytes())?;

    let status_text = if let Some(code) = output.status.code() {
        format!("exit_code={code}\n")
    } else {
        "exit_code=signal\n".to_string()
    };
    write_debug_file(
        debug_dir,
        model,
        "runner_status.txt",
        status_text.as_bytes(),
    )?;

    Ok(())
}

fn write_debug_file(
    debug_dir: &Path,
    model: &str,
    suffix: &str,
    contents: &[u8],
) -> Result<(), String> {
    let path = debug_dir.join(format!("{model}_{suffix}"));
    fs::write(&path, contents)
        .map_err(|e| format!("failed to write debug file {}: {e}", path.display()))
}

fn extract_limits(raw: &str) -> UsageLimits {
    let weekly_limit = extract_keyed_percentage(raw, &["weeklyLimit", "weeklyLImit"])
        .or_else(|| extract_last_percentage(raw))
        .unwrap_or_else(|| "??".to_string());
    let short_term_limit =
        extract_keyed_percentage(raw, &["shortTermLimit"]).unwrap_or_else(|| "??".to_string());

    UsageLimits {
        weekly_limit,
        short_term_limit,
    }
}

fn extract_keyed_percentage(raw: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = extract_percentage_for_key(raw, key) {
            return Some(value);
        }
    }

    None
}

fn extract_percentage_for_key(raw: &str, key: &str) -> Option<String> {
    let double_quoted = format!("\"{key}\"");
    let single_quoted = format!("'{key}'");

    for needle in [double_quoted.as_str(), single_quoted.as_str(), key] {
        let mut cursor = raw;

        while let Some(start) = cursor.find(needle) {
            let remaining = &cursor[start + needle.len()..];

            if let Some(value) = extract_percentage_after_colon(remaining) {
                return Some(value);
            }

            if remaining.is_empty() {
                break;
            }
            cursor = &remaining[1..];
        }
    }

    None
}

fn extract_percentage_after_colon(input: &str) -> Option<String> {
    let colon = input.find(':')?;
    let value = input[colon + 1..].trim_start();

    if value.is_empty() {
        return None;
    }

    let candidate = if let Some(rest) = value.strip_prefix('"') {
        &rest[..rest.find('"')?]
    } else if let Some(rest) = value.strip_prefix('\'') {
        &rest[..rest.find('\'')?]
    } else {
        let end = value
            .find(|c: char| c == ',' || c == '}' || c.is_ascii_whitespace())
            .unwrap_or(value.len());
        &value[..end]
    };

    normalize_percentage(candidate)
}

fn extract_last_percentage(raw: &str) -> Option<String> {
    for token in raw.split_whitespace().rev() {
        if let Some(value) = normalize_percentage(token) {
            return Some(value);
        }
    }

    None
}

fn normalize_percentage(input: &str) -> Option<String> {
    let candidate =
        input.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '%' || c == '?'));

    if candidate == "??" {
        return Some("??".to_string());
    }

    let number = candidate.strip_suffix('%')?;
    if number.is_empty() || !number.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let value = number.parse::<u8>().ok()?;
    if value > 100 {
        return None;
    }

    Some(format!("{value}%"))
}

fn render_json(rows: &[BudgetRow]) -> String {
    let mut out = String::from("[");

    for (idx, row) in rows.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }

        out.push_str("{\"model\":\"");
        out.push_str(&json_escape(row.model));
        out.push_str("\",\"weeklyLimit\":\"");
        out.push_str(&json_escape(&row.weekly_limit));
        out.push_str("\",\"shortTermLimit\":\"");
        out.push_str(&json_escape(&row.short_term_limit));
        out.push_str("\"}");
    }

    out.push(']');
    out
}

fn json_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());

    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::{
        BudgetRow, OutputMode, UsageLimits, extract_limits, json_escape, parse_args, render_json,
    };

    #[test]
    fn extracts_limits_from_json() {
        assert_eq!(
            extract_limits(r#"{"weeklyLimit":"63%","shortTermLimit":"18%"}"#),
            UsageLimits {
                weekly_limit: "63%".to_string(),
                short_term_limit: "18%".to_string(),
            }
        );
    }

    #[test]
    fn extracts_limits_with_unknowns() {
        assert_eq!(
            extract_limits(r#"{"weeklyLimit":"??","shortTermLimit":"??"}"#),
            UsageLimits {
                weekly_limit: "??".to_string(),
                short_term_limit: "??".to_string(),
            }
        );
    }

    #[test]
    fn extracts_weekly_limit_with_legacy_typo_key() {
        assert_eq!(
            extract_limits(r#"{"weeklyLImit":"41%","shortTermLimit":"11%"}"#),
            UsageLimits {
                weekly_limit: "41%".to_string(),
                short_term_limit: "11%".to_string(),
            }
        );
    }

    #[test]
    fn falls_back_to_single_percentage_for_weekly_limit() {
        assert_eq!(
            extract_limits("result: 42%"),
            UsageLimits {
                weekly_limit: "42%".to_string(),
                short_term_limit: "??".to_string(),
            }
        );
    }

    #[test]
    fn parse_args_defaults_to_text() {
        let flags = parse_args(Vec::<String>::new()).expect("parse succeeds");
        assert!(matches!(flags.mode, OutputMode::Text));
        assert!(!flags.debug);
    }

    #[test]
    fn parse_args_supports_json() {
        let flags = parse_args(vec!["--json".to_string()]).expect("parse succeeds");
        assert!(matches!(flags.mode, OutputMode::Json));
        assert!(!flags.debug);
    }

    #[test]
    fn parse_args_supports_debug() {
        let flags = parse_args(vec!["--debug".to_string()]).expect("parse succeeds");
        assert!(matches!(flags.mode, OutputMode::Text));
        assert!(flags.debug);
    }

    #[test]
    fn parse_args_supports_json_and_debug() {
        let flags =
            parse_args(vec!["--json".to_string(), "--debug".to_string()]).expect("parse succeeds");
        assert!(matches!(flags.mode, OutputMode::Json));
        assert!(flags.debug);
    }

    #[test]
    fn parse_args_rejects_unknown_flags() {
        let err = parse_args(vec!["--nope".to_string()]).expect_err("parse fails");
        assert!(err.contains("unknown argument"));
    }

    #[test]
    fn render_json_matches_contract() {
        let rows = [
            BudgetRow {
                model: "codex",
                weekly_limit: "63%".to_string(),
                short_term_limit: "18%".to_string(),
            },
            BudgetRow {
                model: "claude",
                weekly_limit: "??".to_string(),
                short_term_limit: "7%".to_string(),
            },
        ];

        assert_eq!(
            render_json(&rows),
            r#"[{"model":"codex","weeklyLimit":"63%","shortTermLimit":"18%"},{"model":"claude","weeklyLimit":"??","shortTermLimit":"7%"}]"#
        );
    }

    #[test]
    fn json_escape_escapes_quotes_and_backslashes() {
        assert_eq!(json_escape("\"a\\b\""), "\\\"a\\\\b\\\"");
    }
}
