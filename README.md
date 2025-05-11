# Tailscale MCP Server

An MCP (Model Context Protocol) server for Tailscale, enabling detailed queries about devices within your tailnet via Claude Desktop or other compatible LLM clients.

## Features

* Supports MCP interactions over **SSE (Server-Sent Events)** and **stdio**.
* Queries detailed device information by ID, hostname, or IP address.
* Lists all devices within your Tailscale network.
* OAuth Grants middleware integration with Tailscale.

---

## ✅ Installation

### Prerequisites:

* [Go 1.22 or higher](https://golang.org/dl/)
* [Tailscale](https://tailscale.com) account and Admin API key.

### Steps:

1. **Clone the Repository**

   ```bash
   git clone <repo_url>
   cd <repo_dir>
   ```

2. **Install Dependencies**

   ```bash
   go mod tidy
   ```

3. **Build the Binary**

   ```bash
   go build -o tailscale-mcp main.go
   ```

---

## 🔑 API Key Configuration

Before running the server, ensure you have a Tailscale Admin API key:

1. Go to [Tailscale Admin Console](https://login.tailscale.com/admin/settings/keys).
2. Generate an API key with the appropriate permissions (read devices at minimum).
3. Set the following environment variables:

   ```bash
   export TAILSCALE_API_KEY="tskey-yourapikey"
   export TAILSCALE_TAILNET="yourtailnet.com"
   ```

---

## 🚀 Running the MCP Server

### SSE Mode (default):

```bash
./tailscale-mcp
```

* Starts an SSE server accessible via:

  * **Tailscale network**: `http://<hostname>.yourtailnet.ts.net:8080`
  * **Localhost** (Claude Desktop compatibility): `http://127.0.0.1:8080`

### Stdio Mode:

```bash
./tailscale-mcp --stdio
```

* Useful for local debugging or direct integration with certain MCP clients.

---

## 🤖 Using with Claude Desktop

Claude Desktop currently supports **stdio** mode for MCP servers.

### Configuring Claude Desktop:

1. Locate your Claude Desktop MCP config file:

   * **macOS**: `~/Library/Application Support/claude_desktop_config.json`
   * **Windows/Linux**: Refer to Claude documentation.

2. Edit `claude_desktop_config.json`:

```json
   {
    "mcpServers": {
      "tailscale": {
        "command": "/usr/local/bin/tailscale-mcp",
        "args": [
          "--stdio",
          "--tailnet",
          "lbrlabs.com",
          "--api-key",
          "<api-key>",
        ]
      }
    }
  }
```

3. Restart Claude Desktop.
   Claude Desktop will now recognize your MCP server.

---

## 🛠️ Available Tools & Resources

### Resources

| URI                              | Description                                              |
| -------------------------------- | -------------------------------------------------------- |
| `bootstrap://status`             | Health-check endpoint.                                   |
| `tailscale://device`             | Query detailed device info (**limited client support**). |
| `tailscale://policy-file`        | Retrieve the tailnet ACL policy file.                    |
| `tailscale://tailnet-settings`   | Retrieve current tailnet settings and configuration.     |


### Tools (recommended for Claude):

| Tool               | Description                                | Arguments                   |
| ------------------ | ------------------------------------------ | --------------------------- |
| `get_device_info`  | Fetch device details (by ID, IP, hostname) | `device`: Device identifier |
| `list_all_devices` | Lists all devices in your tailnet          | *(no arguments required)*   |

**Note**: Using tools is preferred for Claude as it provides broader compatibility.

---

## 📌 Example Queries (Claude Desktop)

**Get device details**
Prompt:

```
Use get_device_info to get details about device "100.101.102.103"
```

**List all devices**
Prompt:

```
List all devices using the tool list_all_devices
```

---

## 📖 License

This project is open-source software under the MIT license.

---

## 🔗 Useful Links

* [Tailscale API Documentation](https://tailscale.com/kb/1101/api/)
* [Claude Desktop](https://claude.ai)
* [MCP Protocol Documentation](https://modelcontextprotocol.io/)

---
