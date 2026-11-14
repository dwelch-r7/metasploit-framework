from mcp.server.fastmcp import FastMCP

server = FastMCP('Module target native control')


@server.tool()
def native_echo(value: str) -> str:
    """Return the supplied native control marker."""
    return 'module-target-native:' + value


if __name__ == '__main__':
    server.run(transport='stdio')
