# Tailscale MCP Server

An MCP (Model Context Protocol) server for Tailscale, enabling detailed queries about devices, policy files, and tailnet settings via Claude Desktop or other compatible LLM clients. Features comprehensive Tailscale OAuth grants integration for fine-grained access control.

## Features

* **Multiple Server Modes**: Supports both stdio and HTTP (with SSE) modes
* **Comprehensive Tailscale Integration**: Query devices, policy files, and tailnet settings
* **OAuth Grants Authorization**: Fine-grained access control using Tailscale grants with custom MCP capabilities
* **Dual Network Access**: Accessible via both Tailscale network and localhost
* **Claude Desktop Compatible**: Optimized for Claude Desktop integration
* **Flexible Logging**: TTY-aware logging with configurable debug levels

## Prerequisites

* [Tailscale](https://tailscale.com) account with an Admin API key
* Go 1.22 or higher (if building from source)

## Installation

### Download Pre-Built Binaries

Grab the latest pre-built binary for your platform from the release page.

#### macOS

1. Download the latest release archive for macOS (`ts-mcp-<version>-darwin-amd64.tar.gz` or `ts-mcp-<version>-darwin-arm64.tar.gz`)
2. Extract and install:

```bash
tar -xzf ts-mcp-<version>-darwin-*.tar.gz
sudo mv ts-mcp /usr/local/bin/
```

You can also install with homebrew:
```bash
brew install jaxxstorm/tap/ts-mcp
```

#### Linux

1. Download the latest release archive for Linux (`ts-mcp-<version>-linux-amd64.tar.gz` or `ts-mcp-<version>-linux-arm64.tar.gz`)
2. Extract and install:

```bash
tar -xzf ts-mcp-<version>-linux-*.tar.gz
sudo mv ts-mcp /usr/local/bin/
```

#### Windows

1. Download the latest release ZIP archive for Windows (`ts-mcp-<version>-windows-amd64.zip` or `ts-mcp-<version>-windows-arm64.zip`)
2. Extract the binary (`ts-mcp.exe`) and move it to a preferred location, such as `C:\Program Files\ts-mcp\`
3. Add the chosen location to your system's PATH if desired

### Building From Source

If you prefer building the binary from source:

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
go build -o ts-mcp main.go
```

## Configuration

### Required Environment Variables

```bash
export TAILSCALE_API_KEY="tskey-yourapikey"
export TAILSCALE_TAILNET="yourtailnet.com"
```

### Optional Environment Variables

```bash
export TS_HOSTNAME="ts-mcp"          # Tailscale hostname (default: ts-mcp)
export TS_PORT="8080"                # Port to listen on (default: 8080)
export TS_AUTH_KEY=""                # Tailscale auth key for automatic authentication
```

### Command Line Options

* `--debug` / `-d`: Enable debug logging
* `--version` / `-v`: Show version information
* `--stdio`: Use stdio mode instead of HTTP (required for Claude Desktop)

## Getting Your API Key

1. Go to [Tailscale Admin Console](https://login.tailscale.com/admin/settings/keys)
2. Generate an API key with the following permissions:
   - Read devices
   - Read policy file
   - Read tailnet settings

## OAuth Grants & Access Control

This server implements fine-grained access control using Tailscale OAuth grants. You can configure custom MCP capabilities in your Tailscale ACL policy file to control which users can access specific tools and resources.

### ACL Configuration Example

Add the following to your Tailscale ACL policy file:

```json
{
  "grants": [
    {
      "src": ["user:alice@example.com"],
      "dst": ["tag:mcp-server"],
      "app": {
        "jaxxstorm.com/cap/mcp": [{
          "tools": ["*"],
          "resources": ["*"]
        }]
      }
    },
    {
      "src": ["user:bob@example.com"],
      "dst": ["tag:mcp-server"],
      "app": {
        "jaxxstorm.com/cap/mcp": [{
          "tools": ["list_all_devices"],
          "resources": ["bootstrap://status", "tailscale://devices"]
        }]
      }
    }
  ]
}
```

### Grant Permissions

**Tools**: Control which MCP tools users can execute
- `get_device_info`: Allow querying specific device details
- `list_all_devices`: Allow listing all devices
- `*`: Allow all tools

**Resources**: Control which MCP resources users can access
- `bootstrap://status`: Health check endpoint
- `tailscale://devices`: Device list resource
- `tailscale://policy`: Policy file access
- `tailscale://tailnet-settings`: Tailnet settings access
- `tailscale://device`: Individual device resource access
- `*`: Allow all resources

## Running the Server

### HTTP Mode (Default)

```bash
./ts-mcp
```

The server will be accessible via:
* **Tailscale network**: `http://<hostname>.yourtailnet.ts.net:8080/mcp`
* **Localhost**: `http://127.0.0.1:8080/mcp`

### Stdio Mode (Required for Claude Desktop)

```bash
./ts-mcp --stdio
```

## Claude Desktop Integration

Claude Desktop currently supports stdio mode for MCP servers.

### Configuration Steps

1. Locate your Claude Desktop MCP config file:
   * **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   * **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   * **Linux**: `~/.config/Claude/claude_desktop_config.json`

2. Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tailscale": {
      "command": "/usr/local/bin/ts-mcp",
      "args": ["--stdio"],
      "env": {
        "TAILSCALE_API_KEY": "tskey-yourapikey",
        "TAILSCALE_TAILNET": "yourtailnet.com"
      }
    }
  }
}
```

3. Restart Claude Desktop

Claude will now recognize your MCP server and you can interact with your Tailscale network.

## Available Tools & Resources

### Tools (Recommended for Claude)

| Tool | Description | Arguments | Required Grant |
|------|-------------|-----------|----------------|
| `get_device_info` | Fetch device details by ID, IP, or hostname | `device`: Device identifier | `get_device_info` |
| `list_all_devices` | List all devices in your tailnet | None | `list_all_devices` |

### Resources

| URI | Description | Required Grant |
|-----|-------------|----------------|
| `bootstrap://status` | Health-check endpoint | `bootstrap://status` |
| `tailscale://devices` | Complete device list with metadata | `tailscale://devices` |
| `tailscale://policy` | Current Tailscale ACL policy file | `tailscale://policy` |
| `tailscale://tailnet-settings` | Tailnet configuration and settings | `tailscale://tailnet-settings` |
| `tailscale://device` | Individual device details (parameterized) | `tailscale://device` |

**Note**: Tools are preferred for Claude Desktop as they provide better compatibility and error handling.

## Example Claude Desktop Queries

### Get Device Information
```
Use get_device_info to get details about device "100.101.102.103"
```

### List All Devices
```
List all devices in my tailnet using list_all_devices
```

### Check Tailnet Policy
```
Show me the current Tailscale policy by reading the tailscale://policy resource
```

### Monitor Device Status
```
Get the status of my work laptop and show me when it was last seen
```

## Security Features

* **Tailscale OAuth Integration**: Leverages Tailscale's built-in authentication
* **Fine-grained Access Control**: Granular permissions via MCP capabilities in ACL grants
* **Network Isolation**: All communication flows through your private Tailscale network
* **User Context Logging**: Comprehensive audit trail of user actions
* **Origin Validation**: HTTP mode includes origin validation for additional security

## Logging

The server provides comprehensive logging with multiple levels:

* **Default**: Info level with key operations
* **Debug** (`-d`): Detailed protocol-level debugging including OAuth grants inspection

Log output automatically adapts:
* **TTY**: Colorized, human-readable format with timestamps
* **Non-TTY**: Structured JSON for log aggregation systems

## Troubleshooting

### Common Issues

**"No MCP capabilities found"**
- Verify your ACL policy includes the correct grants configuration
- Check that the server node has the appropriate tags
- Ensure the user has been granted access to MCP capabilities

**"Access denied: insufficient permissions"**
- Review the grants configuration in your ACL policy
- Verify the user is listed in the `src` field of the relevant grant
- Check that the requested tool/resource is included in the capability definition

**"Failed to get Tailscale status"**
- Ensure Tailscale is running and authenticated
- Verify the API key has the required permissions
- Check network connectivity to Tailscale coordination servers

### Debug Mode

Enable debug logging to see detailed protocol exchanges and OAuth grants:

```bash
./ts-mcp --debug --stdio
```

This will show:
- Detailed MCP message flow
- OAuth grants parsing and validation
- User authentication context
- Access control decisions

## Dependencies

* `github.com/alecthomas/kong` - CLI parsing
* `github.com/mark3labs/mcp-go` - MCP protocol implementation
* `github.com/tailscale/hujson` - HuJSON parsing for policy files
* `go.uber.org/zap` - Structured logging
* `golang.org/x/term` - TTY detection
* `tailscale.com/client/tailscale/v2` - Tailscale API client
* `tailscale.com/tsnet` - Tailscale network integration

## Version

Current version: **0.0.2**

Use `./ts-mcp --version` to check your installed version.

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]

## Useful Links

* [Tailscale API Documentation](https://tailscale.com/kb/1101/api/)
* [Tailscale OAuth Grants](https://tailscale.com/kb/1017/grant-access-to-apps/)
* [Claude Desktop](https://claude.ai)
* [MCP Protocol Documentation](https://modelcontextprotocol.io/)