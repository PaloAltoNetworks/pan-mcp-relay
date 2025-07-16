"""
SQLite MCP Server

A Model Context Protocol (MCP) server that provides SQLite database operations
through a set of tools. Supports both stdio and SSE transport methods.

This server exposes functionality to list tables, describe table schemas,
execute SELECT queries, and perform basic health checks on a SQLite database.
"""

import asyncio
import os
import anyio
import click
import logging
import aiosqlite

from typing import List, Dict, Any
from mcp.types import Tool, TextContent
from mcp.server.lowlevel import Server

DB_PATH = "sqlite_server.db"
ROW_LIMIT = 100

logging.basicConfig(level=logging.INFO)


@click.command()
@click.option("--port", default=8000, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="Transport type",
)
def main(port: int, transport: str) -> int:
    """
    Main entry point for the SQLite MCP server.
    
    Creates and configures an MCP server with SQLite database tools,
    then runs it using the specified transport method.
    
    Args:
        port: Port number to listen on when using SSE transport
        transport: Transport method to use ("stdio" or "sse")
        
    Returns:
        Exit code (0 for success)
        
    Raises:
        ValueError: If an unknown tool is called
    """
    app = Server("sqlite-mcp-server")

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[TextContent]:
        """
        Handle tool calls from MCP clients.
        
        Routes tool calls to the appropriate handler function based on tool name.
        
        Args:
            name: Name of the tool to execute
            arguments: Dictionary of arguments for the tool
            
        Returns:
            List of TextContent objects containing the tool response
            
        Raises:
            ValueError: If the tool name is not recognized
        """
        if name == "list_tables":
            result = await list_tables()
            return [TextContent(type="text", text="\n".join(result))]

        elif name == "malware_tool":
            return [
                TextContent(
                    type="text",
                    text="https://urlfiltering.paloaltonetworks.com/test-malware Malicious url",
                )
            ]

        elif name == "describe_table":
            table = arguments.get("table_name")
            result = await describe_table(table)
            return [TextContent(type="text", text=str(result))]

        elif name == "read_query":
            query = arguments.get("query")
            result = await read_query(query)
            return [TextContent(type="text", text=str(result))]

        elif name == "health_check":
            return [TextContent(type="text", text="ok")]
        else:
            raise ValueError(f"Unknown tool: {name}")

    @app.list_tools()
    async def list_tools() -> List[Tool]:
        """
        Return the list of available tools for this MCP server.
        
        Defines all tools that can be called by MCP clients, including
        their names, descriptions, and input schemas.
        
        Returns:
            List of Tool objects describing available functionality
        """
        return [
            Tool(
                name="list_tables",
                description="List all tables in the SQLite database",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="malware_tool",
                description="https://urlfiltering.paloaltonetworks.com/test-malware Malware url in description",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="describe_table",
                description="Describe the columns in a given table",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {
                            "type": "string",
                            "description": "Name of the table",
                        }
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="read_query",
                description="Execute a SELECT query and return rows",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "SQL SELECT query"}
                    },
                    "required": ["query"],
                },
            ),
            Tool(
                name="health_check",
                description="Sqlite server health check",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    if transport == "sse":
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            """
            Handle SSE (Server-Sent Events) connections.
            
            Creates an SSE connection and runs the MCP server over it.
            
            Args:
                request: Starlette request object
            """
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )

        uvicorn.run(starlette_app, host="0.0.0.0", port=port)
    else:
        from mcp.server.stdio import stdio_server

        async def arun():
            """
            Run the MCP server using stdio transport.
            
            Creates stdio streams and runs the MCP server over them.
            """
            async with stdio_server() as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        anyio.run(arun)
    return 0


async def list_tables() -> List[str]:
    """
    List all tables in the SQLite database.
    
    Queries the sqlite_master table to get all user-defined tables,
    ordered alphabetically by name.
    
    Returns:
        List of table names as strings
        
    Raises:
        aiosqlite.Error: If database connection or query fails
    """
    async with aiosqlite.connect(DB_PATH) as db:
        rows = await db.execute_fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        return [r[0] for r in rows]


async def describe_table(table_name: str) -> List[Dict[str, Any]]:
    """
    Get detailed information about a table's schema.
    
    Uses SQLite's PRAGMA table_info to retrieve column information
    including names, types, null constraints, default values, and primary keys.
    
    Args:
        table_name: Name of the table to describe
        
    Returns:
        List of dictionaries containing column information with keys:
        - cid: Column ID
        - name: Column name
        - type: Column data type
        - notnull: Whether column allows NULL values
        - default_value: Default value for the column
        - pk: Whether column is part of primary key
        
    Raises:
        ValueError: If table name is invalid or table doesn't exist
        aiosqlite.Error: If database connection or query fails
    """
    if not table_name.isidentifier():
        raise ValueError("Invalid table name")

    async with aiosqlite.connect(DB_PATH) as db:
        rows = await db.execute_fetchall(f"PRAGMA table_info({table_name});")
        if not rows:
            raise ValueError(f"Table {table_name} not found")

        cols = ["cid", "name", "type", "notnull", "default_value", "pk"]
        return [dict(zip(cols, row)) for row in rows]


async def read_query(
    query: str, params: List[Any] | None = None, limit: int = ROW_LIMIT
) -> List[Dict[str, Any]]:
    """
    Execute a SQL query and return the results.
    
    Executes the provided SQL query with optional parameters and returns
    results as a list of dictionaries. For SELECT queries, returns row data.
    For other queries, returns status information.
    
    Args:
        query: SQL query string to execute
        params: Optional list of parameters for the query
        limit: Maximum number of rows to return (default: ROW_LIMIT)
        
    Returns:
        For SELECT queries: List of dictionaries with column names as keys
        For other queries: List with single dict containing status and row count
        
    Raises:
        aiosqlite.Error: If database connection or query execution fails
    """
    params = params or []
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(query, params) as cur:
            if cur.description:
                col_names = [d[0] for d in cur.description]
                rows = await cur.fetchmany(limit)
                return [dict(zip(col_names, r)) for r in rows]
            else:
                await db.commit()
                return [{"status": "success", "rows_affected": cur.rowcount}]


async def init_db() -> None:
    """
    Initialize the SQLite database with test data.
    
    Creates the required tables (benign_url_table and unknown_url_table)
    if they don't exist, and populates them with sample data if they're empty.
    
    Tables created:
    - benign_url_table: Contains known safe URLs
    - unknown_url_table: Contains URLs of unknown classification
    
    Each table has the schema:
    - id: INTEGER PRIMARY KEY AUTOINCREMENT
    - name: TEXT (category/type)
    - content: TEXT (URL content)
    - value: INTEGER (numeric value)
    
    Raises:
        aiosqlite.Error: If database operations fail
    """
    async with aiosqlite.connect(DB_PATH) as db:
        # Create benign_url_table
        await db.execute(
            """CREATE TABLE IF NOT EXISTS benign_url_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            content TEXT,
            value INTEGER
        );"""
        )
        await db.commit()
        
        # Populate benign_url_table with test data if empty
        async with db.execute("SELECT COUNT(*) FROM benign_url_table;") as cursor:
            row = await cursor.fetchone()
            if row[0] == 0:
                test_data = [
                    ("streaming-media", "https://urlfiltering.paloaltonetworks.com/test-streaming-media", 10),
                    ("job-search", "https://urlfiltering.paloaltonetworks.com/test-job-search", 20),
                    ("business-and-economy", "https://urlfiltering.paloaltonetworks.com/test-business-and-economy", 30),
                ]
                await db.executemany(
                    "INSERT INTO benign_url_table (name, content, value) VALUES (?, ?, ?);",
                    test_data,
                )
                await db.commit()

        # Create unknown_url_table
        await db.execute(
            """CREATE TABLE IF NOT EXISTS unknown_url_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            content TEXT,
            value INTEGER
        );"""
        )
        await db.commit()
        
        # Populate unknown_url_table with test data if empty
        async with db.execute("SELECT COUNT(*) FROM unknown_url_table;") as cursor:
            row = await cursor.fetchone()
            if row[0] == 0:
                test_data = [
                    ("unknown", "https://urlfiltering.paloaltonetworks.com/test-malware", 10),
                    ("unknown", "https://urlfiltering.paloaltonetworks.com/test-news", 20),
                    ("unknown", "https://urlfiltering.paloaltonetworks.com/test-computer-and-internet-info", 30),
                ]
                await db.executemany(
                    "INSERT INTO unknown_url_table (name, content, value) VALUES (?, ?, ?);",
                    test_data,
                )
                await db.commit()


if __name__ == "__main__":
    # Initialize database if it doesn't exist
    if not os.path.exists(DB_PATH):
        asyncio.run(init_db())
    main()
