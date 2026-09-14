# demo.tape — VHS script for the AgentGov terminal demo
#
# Renders a GIF/MP4 of `examples/live_demo.py` running end to end: governing
# an agent in two lines, halting an adversarial runaway loop, then verifying
# and reconciling the resulting ledger.
#
# Requires the `vhs` CLI (https://github.com/charmbracelet/vhs):
#
#   brew install vhs        # or: go install github.com/charmbracelet/vhs@latest
#   vhs demo.tape
#
# Produces demo.gif in the repository root.

Output demo.gif

Require uv

# Dark theme, wide enough for the reconciliation table (62 columns) with
# comfortable margin at a readable 18pt font. 1500px / 18pt monospace
# comfortably clears 100 columns.
Set Shell "bash"
Set FontSize 18
Set FontFamily "JetBrains Mono"
Set Width 1500
Set Height 1000
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms
Set CursorBlink true

Hide
Type "clear"
Enter
Sleep 500ms
Show

# --- Setup: make sure the terminal starts from a clean slate -------------
Type "rm -rf demo"
Enter
Sleep 1s

# --- The live demo: adopt, halt a runaway, then prove the books ----------
Type "uv run python examples/live_demo.py"
Enter

# Give the header and Act 1 (two-line adoption + real work) time to land.
Sleep 6s

# Act 2: the adversarial runaway loop and the cognitive breaker's halt.
Sleep 6s

# The measured latency and the "breaker latches" retry-storm proof.
Sleep 5s

# The closing summary panel.
Sleep 5s

# --- Step 3: prove the ledger is intact -----------------------------------
Type "uv run agentgov inspect demo/governor.db"
Enter
Sleep 6s

# --- Step 4: prove there was no unmetered spend ---------------------------
Type "uv run agentgov reconcile demo/governor.db demo/provider_invoice.json --journal demo/tokens.jsonl"
Enter
Sleep 6s

# Hold on the final frame so the audit verdict is readable.
Sleep 3s
