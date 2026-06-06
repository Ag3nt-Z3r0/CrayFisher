# note-keeper

A tiny MCP server that lets an assistant save and recall notes in the user's
workspace (`~/agent-ws`). Runs over stdio; containerized via the included
Dockerfile.

Tools:
- `save_note(name, content)` — write a note into the workspace.
