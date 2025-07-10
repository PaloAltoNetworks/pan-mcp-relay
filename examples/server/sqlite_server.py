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
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio", help="Transport type")
def main(port: int, transport: str) -> int:
    app = Server("sqlite-mcp-server")

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[TextContent]:
        if name == "list_tables":
            result = await list_tables()
            return [TextContent(type="text", text="\n".join(result))]

        elif name == "malware_tool":
            return [TextContent(type="text", text="https://urlfiltering.paloaltonetworks.com/test-malware Malicious url")]
        
        elif name == "describe_table":
            table = arguments.get("table_name")
            result = await describe_table(table)
            return [TextContent(type="text", text=str(result))]

        elif name == "read_query":
            query = arguments.get("query")
            result = await read_query(query)
            return [TextContent(type="text", text=str(result))]

        elif name == "ping":
            return [TextContent(type="text", text="pong")]
        else:
            raise ValueError(f"Unknown tool: {name}")

    @app.list_tools()
    async def list_tools() -> List[Tool]:
        return [
            Tool(
                name="list_tables",
                description="List all tables in the SQLite database",
                inputSchema={"type": "object", "properties": {}}
            ),
            Tool(
                name="malware_tool",
                description="https://urlfiltering.paloaltonetworks.com/test-malware Malware url in description",
                inputSchema={"type": "object", "properties": {}}
            ),
            Tool(
                name="describe_table",
                description="Describe the columns in a given table",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Name of the table"}
                    },
                    "required": ["table_name"]
                }
            ),
            Tool(
                name="read_query",
                description="Execute a SELECT query and return rows",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "SQL SELECT query"}
                    },
                    "required": ["query"]
                }
            ),
            Tool(
                name="ping",
                description="sqlite ping pong",
                inputSchema={'type': 'object', 'properties': {}}
            )
        ]

    if transport == "sse":
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())

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
            async with stdio_server() as streams:
                await app.run(streams[0], streams[1], app.create_initialization_options())

        anyio.run(arun)
    return 0


async def list_tables() -> List[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        rows = await db.execute_fetchall("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        return [r[0] for r in rows]


async def describe_table(table_name: str) -> List[Dict[str, Any]]:
    if not table_name.isidentifier():
        raise ValueError("Invalid table name")

    async with aiosqlite.connect(DB_PATH) as db:
        rows = await db.execute_fetchall(f"PRAGMA table_info({table_name});")
        if not rows:
            raise ValueError(f"Table {table_name} not found")

        cols = ["cid", "name", "type", "notnull", "default_value", "pk"]
        return [dict(zip(cols, row)) for row in rows]


async def read_query(query: str, params: List[Any] | None = None, limit: int = ROW_LIMIT) -> List[Dict[str, Any]]:
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
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""CREATE TABLE IF NOT EXISTS benign_url_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            content TEXT,
            value INTEGER
        );""")
        await db.commit()
        async with db.execute("SELECT COUNT(*) FROM benign_url_table;") as cursor:
            row = await cursor.fetchone()
            if row[0] == 0:
                test_data = [("search_engine", "www.google.com", 10), ("news", "www.reuters.com", 20), ("news", "www.cnn.com", 30)]
                await db.executemany("INSERT INTO benign_url_table (name, content, value) VALUES (?, ?, ?);", test_data)
                await db.commit()

        await db.execute("""CREATE TABLE IF NOT EXISTS unknown_url_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            content TEXT,
            value INTEGER
        );""")
        await db.commit()
        async with db.execute("SELECT COUNT(*) FROM unknown_url_table;") as cursor:
            row = await cursor.fetchone()
            if row[0] == 0:
                test_data = [("unknown", "jukoxiu.dazoqao.xyz", 10), ("unknown", "www.reuters.com", 20), ("unknown", "www.cnn.com", 30)]
                await db.executemany("INSERT INTO unknown_url_table (name, content, value) VALUES (?, ?, ?);", test_data)
                await db.commit()


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        asyncio.run(init_db())
    main()
