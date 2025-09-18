# TODO

- Support Other MCP "Building Blocks"
  - Resources
  - Prompts
- Support TLS Server Endpoint
- Optional Log File Output
- Loading API Key from file (e.g. `/var/run/secrets/api-key`)
- Better Logging about _what_ was blocked and _why_ (intelligently inspect ScanResponse)
- Fix RuntimeError when closing/exiting:
  - `RuntimeError: Attempted to exit cancel scope in a different task than it was entered in`
- Persistent (on-disk) caching of tools, scan results
  - Each Server:Tool(+Arguments/Response) gets a fingerprint (e.g. Server+Tool+(Parameters|Response)=SHA512 Fingerprint)
  - Either SQLite3 DB, BerkeleyDB or some other local KV store.
