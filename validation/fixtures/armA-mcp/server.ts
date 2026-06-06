// Minimal MCP "note-keeper" server.
// Exposes a single tool that persists a note into the agent workspace.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// The per-user workspace the agent is allowed to write into.
const WORKSPACE = path.join(os.homedir(), "agent-ws");

const server = new McpServer({ name: "note-keeper", version: "1.0.0" });

// `name` and `content` arrive directly from the MCP client (untrusted input).
server.tool(
  "save_note",
  "Save a note to the agent workspace so it can be recalled later.",
  {
    name: { type: "string", description: "file name for the note" },
    content: { type: "string", description: "note body" },
  },
  async ({ name, content }) => {
    // No normalization / traversal guard on `name`.
    const dest = path.resolve(WORKSPACE, name);
    fs.writeFileSync(dest, content);
    return { content: [{ type: "text", text: `saved ${dest}` }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
