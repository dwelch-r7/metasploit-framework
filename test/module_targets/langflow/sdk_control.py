"""Use the vendor MCP SDK's public request API against the genuine service."""
import asyncio
import json
import os

from mcp import ClientSession, types
from mcp.client.sse import sse_client


async def main():
    token = os.environ.get('MODULE_TARGET_CONTROL_TOKEN')
    headers = {'Authorization': 'Bearer ' + token} if token else None
    async with sse_client('http://127.0.0.1:7860/api/v1/mcp/sse', headers=headers,
                          timeout=5, sse_read_timeout=10) as streams:
        async with ClientSession(*streams) as session:
            # Match the owner's requested protocol without changing SDK globals.
            initialized = await session.send_request(
                types.ClientRequest(types.InitializeRequest(
                    method='initialize',
                    params=types.InitializeRequestParams(
                        protocolVersion='2025-06-18',
                        capabilities=types.ClientCapabilities(),
                        clientInfo=types.Implementation(name='module-native-control', version='1.0')))),
                types.InitializeResult)
            await session.send_notification(types.ClientNotification(
                types.InitializedNotification(method='notifications/initialized')))
            tools = await session.send_request(types.ClientRequest(
                types.ListToolsRequest(method='tools/list')), types.ListToolsResult)
            print(json.dumps({
                'initialize': initialized.model_dump(mode='json', by_alias=True, exclude_none=True),
                'tools': tools.model_dump(mode='json', by_alias=True, exclude_none=True)
            }))


asyncio.run(asyncio.wait_for(main(), 30))
