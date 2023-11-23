from p2pfs.core.exceptions import ServerRunningError
import logging
import asyncio
from abc import abstractmethod
logger = logging.getLogger(__name__)

#server states
_is_running = False
_server_address = None
_writers = set()
_server = None

def is_running():
        return _is_running

async def start(local_address, loop=None):
    if _is_running:
        raise ServerRunningError()
    logger.info('Start listening on {}'.format(local_address))
    _server = await asyncio.start_server(__new_connection, *local_address, loop=loop)
    _server_address = _server.sockets[0].getsockname()[:2]
    _is_running = True

async def stop():
    if _is_running:
        logger.warning('Shutting down {}'.format())
        _is_running = False
        _server.close()
        await _server.wait_closed()
        for writer in set(_writers):
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            if len(_writers) != 0:
                logger.warning('Writers not fully cleared {}'.format(_writers))
            _writers = set()

async def __new_connection(reader, writer):
    _writers.add(writer)
    try:
        await _process_connection(reader, writer)
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        _writers.remove(writer)

    @abstractmethod
    async def _process_connection(reader, writer):
        raise NotImplementedError