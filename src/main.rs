use std::env;
use std::process::{Command, ExitCode};

const CODEX_SCRIPT: &str = r#"
set -euo pipefail

SESSION="codex_usage_$$"
SOCKET="/tmp/agent_budget_codex_${SESSION}.sock"

# Start an interactive shell inside tmux and launch Codex from within it.
tmux -S "$SOCKET" new-session -d -s "$SESSION" "bash"

# Always clean up the tmux session
trap 'tmux -S "$SOCKET" kill-session -t "$SESSION" 2>/dev/null || true; rm -f "$SOCKET"' EXIT

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

PROMPT='Determine the percentage REMAINING for the week. return ONLY A PERCENTAGE, i.e. `63%`, NO OTHER TEXT. IF YOU ARE UNSURE, PRINT ??'

claude -p "$(printf "%s\\n\\n%s" "$PROMPT" "$USAGE_OUTPUT_CLEAN")"
"#;

const CLAUDE_SCRIPT: &str = r#"
set -euo pipefail

SESSION="claude_usage_$$"
SOCKET="/tmp/agent_budget_claude_${SESSION}.sock"

# Start an interactive shell inside tmux and launch Claude from within it.
tmux -S "$SOCKET" new-session -d -s "$SESSION" "bash"

# Always clean up the tmux session
trap 'tmux -S "$SOCKET" kill-session -t "$SESSION" 2>/dev/null || true; rm -f "$SOCKET"' EXIT

tmux -S "$SOCKET" send-keys -t "$SESSION" -l "IS_SANDBOX=1 claude --dangerously-skip-permissions"
tmux -S "$SOCKET" send-keys -t "$SESSION" Enter

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
USAGE_OUTPUT_CLEAN="$(printf "%s" "$USAGE_OUTPUT" | perl -pe "s/\\e\\[[0-9;]*[A-Za-z]//g")"

PROMPT='Determine the percentage REMAINING for the week. return ONLY A PERCENTAGE, i.e. `63%`, NO OTHER TEXT. IF YOU ARE UNSURE, PRINT ??'

exec claude -p "$(printf "%s\\n\\n%s" "$PROMPT" "$USAGE_OUTPUT_CLEAN")"
"#;

struct BudgetRow {
    model: &'static str,
    weekly_remaining: String,
}

#[derive(Debug)]
enum OutputMode {
    Text,
    Json,
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
    let mode = parse_args(env::args().skip(1))?;

    let codex_remaining = run_usage_script(CODEX_SCRIPT)?;
    let claude_remaining = run_usage_script(CLAUDE_SCRIPT)?;

    let rows = [
        BudgetRow {
            model: "codex",
            weekly_remaining: codex_remaining,
        },
        BudgetRow {
            model: "claude",
            weekly_remaining: claude_remaining,
        },
    ];

    match mode {
        OutputMode::Json => {
            let json = render_json(&rows);
            println!("{json}");
        }
        OutputMode::Text => {
            for row in rows {
                println!("{} weekly remaining: {}", row.model, row.weekly_remaining);
            }
        }
    }

    Ok(())
}

fn parse_args<I>(args: I) -> Result<OutputMode, String>
where
    I: IntoIterator<Item = String>,
{
    let mut mode = OutputMode::Text;

    for arg in args {
        match arg.as_str() {
            "--json" => mode = OutputMode::Json,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(mode)
}

fn print_help() {
    println!("agent-budget");
    println!();
    println!("Usage:");
    println!("  agent-budget [--json]");
    println!();
    println!("Options:");
    println!("  --json       Print results as JSON");
    println!("  -h, --help   Print help");
}

fn run_usage_script(script: &str) -> Result<String, String> {
    let output = Command::new("bash")
        .arg("-lc")
        .arg(script)
        .output()
        .map_err(|e| format!("failed to run bash: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!("usage command failed: {detail}"));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    Ok(extract_percentage(&raw))
}

fn extract_percentage(raw: &str) -> String {
    for token in raw.split_whitespace().rev() {
        let candidate =
            token.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '%' || c == '?'));

        if candidate == "??" {
            return "??".to_string();
        }

        if let Some(number) = candidate.strip_suffix('%') {
            if number.is_empty() || !number.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            if let Ok(value) = number.parse::<u8>() {
                if value <= 100 {
                    return format!("{value}%");
                }
            }
        }
    }

    "??".to_string()
}

fn render_json(rows: &[BudgetRow]) -> String {
    let mut out = String::from("[");

    for (idx, row) in rows.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }

        out.push_str("{\"model\":\"");
        out.push_str(&json_escape(row.model));
        out.push_str("\",\"weeklyRemaining\":\"");
        out.push_str(&json_escape(&row.weekly_remaining));
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
    use super::{BudgetRow, OutputMode, extract_percentage, json_escape, parse_args, render_json};

    #[test]
    fn extracts_clean_percentage() {
        assert_eq!(extract_percentage("63%\n"), "63%");
    }

    #[test]
    fn extracts_percentage_from_extra_text() {
        assert_eq!(extract_percentage("result: 42% done"), "42%");
    }

    #[test]
    fn returns_unknown_for_invalid_values() {
        assert_eq!(extract_percentage("150%"), "??");
    }

    #[test]
    fn supports_explicit_unknown() {
        assert_eq!(extract_percentage("??"), "??");
    }

    #[test]
    fn parse_args_defaults_to_text() {
        let mode = parse_args(Vec::<String>::new()).expect("parse succeeds");
        assert!(matches!(mode, OutputMode::Text));
    }

    #[test]
    fn parse_args_supports_json() {
        let mode = parse_args(vec!["--json".to_string()]).expect("parse succeeds");
        assert!(matches!(mode, OutputMode::Json));
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
                weekly_remaining: "63%".to_string(),
            },
            BudgetRow {
                model: "claude",
                weekly_remaining: "??".to_string(),
            },
        ];

        assert_eq!(
            render_json(&rows),
            r#"[{"model":"codex","weeklyRemaining":"63%"},{"model":"claude","weeklyRemaining":"??"}]"#
        );
    }

    #[test]
    fn json_escape_escapes_quotes_and_backslashes() {
        assert_eq!(json_escape("\"a\\b\""), "\\\"a\\\\b\\\"");
    }
}
