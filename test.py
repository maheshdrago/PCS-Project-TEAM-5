import json

class Client:
    def __init__(self, reader, writer, username):
        self.reader = reader
        self.writer = writer
        self.username = username

    async def send_message(self, message):
        self.writer.write(message.encode())
        await self.writer.drain()

    async def receive_message(self):
        data = await self.reader.read(1000)
        return data.decode()

    def close_connection(self):
        self.writer.close()
    

    async def wait_closed(self):
        await self.writer.wait_closed()

import asyncio

async def handle_client(client, message):
    await client.send_message(message)
    response = await client.receive_message()
    print(f"Received response: {response}")

    await client.send_message(message)
    response = await client.receive_message()
    print(f"Received response: {response}")

    client.close_connection()
    await client.wait_closed()

async def main():
    host = "127.0.0.1"
    port = 8000
    

    users = ["mahesh", "james", "loki", 'ramesh', 'tony']

    clients = []
    tasks = []

    for i in range(len(users)):
        reader, writer = await asyncio.open_connection(host, port)
        client = Client(reader, writer, users[i])
        clients.append(client)

        message = json.dumps({
            "username":users[i]
        })
        task = asyncio.create_task(handle_client(client, message))
        tasks.append(task)

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
