import asyncio
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

class QuicEchoServer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def quic_event_received(self, event):
        if event.data == b'hello':
            response = b'world'
            await self.send(response)

async def main():
    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain('path/to/cert.pem', 'path/to/key.pem')

    async with serve('localhost', 4433, configuration=configuration, create_protocol=QuicEchoServer) as server:
        await server.wait_closed()

if __name__ == '__main__':
    asyncio.run(main())
