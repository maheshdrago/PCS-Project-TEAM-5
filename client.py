import asyncio

async def connect(self, tracker_address):
    # connect to server
    self._tracker_reader, self._tracker_writer = await asyncio.open_connection(*tracker_address)
    try:
        # send out register message
        print('Requesting to register')
        await self._tracker_writer.write("REGISTER")
        await write_message(self._tracker_writer, {
            'type': MessageType.REQUEST_REGISTER,
            'address': self._server_address
        })
        message = await read_message(self._tracker_reader)
        print("message",message)
    except (ConnectionError, RuntimeError, asyncio.IncompleteReadError):
        print('Error occurred during communications with tracker.')
        if not self._tracker_writer.is_closing():
            self._tracker_writer.close()
            await self._tracker_writer.wait_closed()
        raise
    print('Successfully registered.')