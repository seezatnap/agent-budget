# agent-budget

Small Rust CLI that reports weekly remaining usage for Codex and Claude.

## Requirements

- `tmux`
- `codex`
- `claude`

## Install

```bash
cargo install --path .
```

## Usage

```bash
agent-budget
```

Print JSON:

```bash
agent-budget --json
```

Write debug artifacts to `/tmp/agent-budget-debug-*` and print that path to stderr:

```bash
agent-budget --json --debug
```

## Output shape (`--json`)

```json
[{"model":"codex","weeklyRemaining":"50%"},{"model":"claude","weeklyRemaining":"32%"}]
```

## Tests

```bash
cargo test
```

Live integration test (uses real `codex`/`claude` sessions):

```bash
cargo test live_json_output_matches_contract -- --ignored
```
