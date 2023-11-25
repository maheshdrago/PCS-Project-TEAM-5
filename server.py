import asyncio
import json
import requests
import os
import uuid
import random

class FileServer:
    def __init__(self):
        self.peers = set() # Set to store connected peers
        self.peer_mappings = dict()

    async def handle_peer(self, reader, writer):
        peer_address = writer.get_extra_info('peername')
        print(f"New connection from {peer_address}")

        try:
            while True:
                data = await reader.read(100)
                data = data.decode()
                
                if not data:
                    break
                data = json.loads(data)
                message = data["message"]

                if message == "list_peers":
                    peer_list = ", ".join(str(peer) for peer in self.peers)
                    writer.write(peer_list.encode())
                    await writer.drain()

                elif message == "REGISTER":
                    username = data["username"]
                    password = data['password']
                    response = requests.post("http://127.0.0.1:5000/register", json = {"username":username, "password":password})

                    writer.write("REGISTERED".encode())
                    await writer.drain()
                
                elif message == "LOGIN":
                    username = data["username"]
                    password = data["password"]

                    response = requests.get("http://127.0.0.1:5000/login?username={}&password={}".format(username, password))
                    data = response.text
                    if data.lower()=="success":
                        self.peers.add(username)
                        self.peer_mappings[peer_address] = username

                        writer.write("Sucess".encode())
                    else:
                        writer.write("Fail".encode())

                    await writer.drain()

                elif message == "CREATE":
                    file_path = data.get("file_path")
                    await self.receive_file(reader,writer, file_path)

                    writer.write("Sucess".encode())
                    await writer.drain()
                else:
                    print(f"Received invalid message from {peer_address}: {message}")

        except asyncio.CancelledError:
            pass
        finally:
            print("Connection from {} ({}) closed".format(username, peer_address))
            username = self.peer_mappings[peer_address]
            self.peers.remove(username)

            writer.close()
            await writer.wait_closed()
    
    def select_random_peer(self):
        return random.choice(list(self.peers))
    
    def generate_chunk_id(self):
        return str(uuid.uuid4())

    async def receive_file(self, reader,writer, file_path):
        try:
            while True:
             
                random_peer = self.select_random_peer()
                
                if not os.path.exists("./peer_data/{}".format(random_peer)):
                    os.mkdir("./peer_data/{}".format(random_peer))
                    
                chunk_path = "./peer_data/{}/".format(random_peer)
                chunk_id = self.generate_chunk_id()
                chunk = await reader.read(1024)

                if not chunk:
                    print("No Data")
                    break

                with open(chunk_path+str(chunk_id)+'.txt', 'wb') as file:
                    file.write(chunk)
                print("Stored chunk with id {} in peer {}".format(chunk_id, random_peer))

            return
        except FileNotFoundError:
            print(f"File not found: {file_path}")

    async def start_server(self, host, port):
        server = await asyncio.start_server(
            self.handle_peer, host, port
        )

        addr = server.sockets[0].getsockname()
        print(f'Serving on {addr}')

        async with server:
            await server.serve_forever()
    


if __name__ == "__main__":
    file_server = FileServer()
    host, port = "127.0.0.1", 8888  # Change the host and port as needed
    asyncio.run(file_server.start_server(host, port))
