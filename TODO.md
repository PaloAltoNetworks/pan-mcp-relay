# TODO

- Support Other MCP "Building Blocks"
  - Resources
  - Prompts
- Support Streamable HTTP Server
- Support TLS Server Endpoint
- Optional Log File Output
- Loading API Key from file (e.g. `/var/run/secrets/api-key`)
- Better Logging about _what_ was blocked and _why_ (intelligently inspect ScanResponse)
- Fix RuntimeError when closing/exiting:
  - `RuntimeError: Attempted to exit cancel scope in a different task than it was entered in`
- Persistent (on-disk) caching of tools, scan results
  - Each Server:Tool gets a fingerprint (e.g. Server+Tool+Description=SHA512 Fingerprint)
