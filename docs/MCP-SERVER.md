# MCP Server Documentation

## Overview

The MCP (Model Context Protocol) server handles tool execution for the autonomous agent.

## Tools Available

### run_nmap
Executes network scanning with nmap

### run_masscan
High-speed network scanner

### write_file
Write or create files on the system

### read_file
Read file contents

## Configuration

The server runs on localhost and communicates with the agent via MCP protocol.

Available tools are registered in the `SUPPORTED_TOOLS` list in `mcp_server.py`;
add or modify entries there to change the tool arsenal.

## Security Considerations

- MCP server should never be exposed to untrusted networks
- All tool execution is logged and monitored by Suricata
- File operations are restricted to intended directories
