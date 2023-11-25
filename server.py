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
    
    async def download_file(self, reader, writer, file_name):
        response = requests.get("http://127.0.0.1:5000/retrieveChunks?filename={}".format(file_name))
        data = response.json()

        if data["status"]=="success":
            chunks = data["chunks"]
            chunks.sort(key = lambda x: x["chunk_number"])

            peers = set()

            for i in chunks:
                peers.add(i['chunk_peer'])
            
            if self.peers==peers:
                with open("./downloads/{}".format(file_name), 'wb') as output:
                    chunk = None
                    for item in chunks:
                        with open("./peer_data/{}/{}.txt".format(item['chunk_peer'], item["chunk_id"]), 'rb') as input:
                            chunk = input.read()

                            output.write(chunk)
                            print("Downloaded Chunk {} from peer {}".format(item["chunk_id"], item["chunk_peer"]))
                
                writer.write('File Downloaded Successfully!!'.encode())
                await writer.drain()
            else:
                writer.write("Not enough peers to download the file!! Try again later.".encode())
                await writer.drain()
        
        else:
            writer.write("File not found!!".encode())
            await writer.drain()

    async def delete_file(self, reader, writer, file_name):
        response = response = requests.get("http://127.0.0.1:5000/deleteChunks?filename={}".format(file_name))
        data = response.json()

        if data["status"]=="success":
            chunks = data["chunks"]

            for chunk in chunks:
                path = "./peer_data/{}/{}.txt".format(chunk["chunk_peer"], chunk["chunk_id"])
                os.remove(path)

                print("Deleted chunk {}".format(chunk["chunk_id"]))
            
            writer.write("Deleted File Successfully!".encode())
            await writer.drain()
        
        else:
            writer.write("Download Failed!!")
            await writer.drain()

    async def receive_file(self, reader,writer, file_path):
        try:
            filename = file_path.split("\\")[-1]
            print(filename, file_path)
            chunk_pieces = []
            chunk_number = 1

            with open(file_path, 'rb') as file:
                try:
                    while True:
                        chunk = file.read(1024)
                        if not chunk:
                            break

                        random_peer = self.select_random_peer()
                
                        if not os.path.exists("./peer_data/{}".format(random_peer)):
                            os.mkdir("./peer_data/{}".format(random_peer))
                            
                        chunk_path = "./peer_data/{}/".format(random_peer)
                        chunk_id = self.generate_chunk_id()

                        with open(chunk_path+str(chunk_id)+'.txt', 'wb') as output_file:
                            output_file.write(chunk)
                        
                        chunk_pieces.append({
                            'chunk_peer':random_peer,
                            'chunk_number':chunk_number,
                            'chunk_id': str(chunk_id)
                        })

                        chunk_number+=1

                        print("Stored chunk with id {} in peer {}".format(chunk_id, random_peer))
                            
                finally:
                    file.close()
            
            response = requests.post("http://127.0.0.1:5000/addChunkMapping", json = {"pieces":chunk_pieces, "filename":filename})
            
            writer.write("File received".encode())
            await writer.drain()
            
        except FileNotFoundError:
            print(f"File not found: {file_path}")


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
                    receive_file_task = asyncio.create_task(self.receive_file(reader, writer, file_path))
                    await receive_file_task
                
                elif message == "DOWNLOAD":
                    filename = data["filename"]
                    await self.download_file(reader, writer, filename)
                
                elif message == "DELETE":
                    filename = data["filename"]
                    await self.delete_file(reader, writer, filename)

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
