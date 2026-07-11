## ADDED Requirements

### Requirement: tsnet logs use application logging
The system SHALL route tsnet Streamable HTTP startup and lifecycle logs through the same application logger and output format used by the MCP server.

#### Scenario: tsnet emits user-visible startup logs
- **WHEN** tsnet emits user-visible startup or lifecycle log messages during Streamable HTTP startup
- **THEN** those messages are written through the application logger with the same output format as other server logs

#### Scenario: Server starts without debug logging
- **WHEN** the server starts without debug logging enabled
- **THEN** normal tsnet user-visible logs use the application logger and verbose backend tsnet logs remain quiet

#### Scenario: Server starts with debug logging
- **WHEN** the server starts with debug logging enabled
- **THEN** verbose backend tsnet logs are also routed through the application logger at debug level

#### Scenario: Stdio mode is selected
- **WHEN** the server starts with the stdio flag
- **THEN** stdio behavior remains unchanged and no tsnet logger setup is required
