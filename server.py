import asyncio
import json
import requests
import os
import uuid
import random
import base64
import fcntl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class FileServer:
    def __init__(self):
        self.peers = set() # Set to store connected peers
        self.peer_mappings = dict()
        self.ip_registrations = dict()
        self.username = ""
        self.locks = {}
    
    async def download_file(self, reader, writer, file_name):
        response = requests.get("http://127.0.0.1:5000/retrieveChunks?filename={}".format(file_name))
        data = response.json()
        
        extension = file_name.split(".")[-1]

        if data["status"]=="success":
            chunks = data["chunks"]
            chunks.sort(key = lambda x: x["chunk_number"])

            peers = set()
            
            print(self.peers)
            for i in chunks:
                peers.add(i['chunk_peer'])
            print(peers)
            if self.peers==peers:
                mode = 'wb' if extension=="exe" else 'w'
                with open("./downloads/{}".format(file_name), mode) as output:
                    chunk = None
                    for item in chunks:
                        with open("./peer_data/{}/{}.bin".format(item['chunk_peer'], item["chunk_id"]), 'rb') as input:
                            chunk = input.read()
                            if extension != "exe":
                                chunk = chunk.decode()
                                
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
        extension = file_name.split(".")[-1]
        read_mode = 'r' if extension!='exe' else 'rb'
        write_mode = 'w' if extension!='exe' else 'wb'

        if data["status"]=="success":
            chunks = data["chunks"]
        
            with open("./recycle_bin/{}".format(file_name), write_mode) as f:
                for chunk in chunks:
                    path = "./peer_data/{}/{}.{}".format(chunk["chunk_peer"], chunk["chunk_id"], "bin")
                    
                    with open(path, read_mode) as i:
                        piece = i.read()
                        f.write(piece)

                    os.remove(path)

                    print("Deleted chunk {}".format(chunk["chunk_id"]))

            
            writer.write("Deleted File Successfully!".encode())
            await writer.drain()
        
        else:
            writer.write("Deletion Failed!!".encode())
            await writer.drain()
    
    async def restore_file(self, reader, writer, file_name):
        try:
            path = "./recycle_bin/{}".format(file_name)
            await self.receive_file(reader, writer, path)

        except Exception as e:
            print(str(e.args()))

    
    async def receive_file(self, reader, writer, file_path):
        try:

            print(file_path)
            filename = file_path.split("\\")[-1] if "\\" in file_path else file_path.split("/")[-1]
            chunk_pieces = []
            chunk_number = 1

            with open(file_path, 'rb') as file:
                try:

                    while True:
                        random_peer = self.select_random_peer()
                        chunk = file.read(1024)
                        if not chunk:
                            break

                        chunk_id = self.generate_chunk_id()

                        if not os.path.exists("./peer_data/{}".format(random_peer)):
                            os.mkdir("./peer_data/{}".format(random_peer))
                            
                        chunk_path = "./peer_data/{}/".format(random_peer)
                        extension = filename.split(".")[-1]
                        
                        
                        if extension!='exe':
                            with open(chunk_path+str(chunk_id)+'.{}'.format("bin"), 'wb') as output_file:
                                output_file.write(chunk)
                        else:
                            with open(chunk_path+str(chunk_id)+'.{}'.format("bin"), 'wb') as output_file:
                                output_file.write(chunk)
                                chunk_number += 1

                        chunk_pieces.append({
                            'chunk_peer': random_peer,
                            'chunk_number': chunk_number,
                            'chunk_id': str(chunk_id)
                        })

                        print("Stored chunk with id {} in peer {}".format(chunk_id, random_peer))
                except Exception as e:
                    print(str(e.args))
                finally:
                    file.close()

            response = requests.post("http://127.0.0.1:5000/addChunkMapping", json={"pieces": chunk_pieces, "filename": filename})

            writer.write("File received".encode())
            await writer.drain()

        except FileNotFoundError:
            print(f"File not found: {file_path}")

    async def send_chunk_to_peer(self, chunk_id, chunk, filename, chunk_number, chunk_pieces):
        random_peer = self.select_random_peer()
        peer_port = self.ip_registrations[random_peer]

        try:
            peer_reader, peer_writer = await asyncio.open_connection('127.0.0.1', peer_port)

            data = {
                "chunk_id": chunk_id,
                "chunk_number": chunk_number,
                "filename": filename,
                "chunk": base64.b64encode(chunk).decode(),
            }

            json_data = json.dumps(data)
            encoded_data = json_data.encode()

            peer_writer.write(encoded_data)
            await peer_writer.drain()

            chunk_pieces.append({
                'chunk_peer': random_peer,
                'chunk_number': chunk_number,
                'chunk_id': str(chunk_id)
            })

            print("Stored chunk with id {} in peer {}".format(chunk_id, random_peer))
        except Exception as e:
            print(f"Error sending chunk to peer {random_peer}: {str(e)}")
        finally:
            if peer_writer:
                peer_writer.close()
                await peer_writer.wait_closed()

            if peer_reader:
                peer_reader.feed_eof()
                peer_reader.close()

    def add_auth(self, filename, permissions):
        for i in permissions:
            print(permissions[i])
            res = requests.post("http://127.0.0.1:5000/addPermissions", json={"username": i, "filename": filename, "permissions":",".join(permissions[i])})

            res = res.json()
            print(res)
            if res["status"] == "Success":
                print("Permission Added for ".format(i))
            else:
                print("Permission addition failed for {}".format(i))

    def set_lock(self, filename):
        if not filename in self.locks:
            self.locks[filename] = self.username
            return True
        else:
            return False
        
    def release_lock(self, filename):
        if filename in self.locks:
            del self.locks[filename]
            return True
        return False
    
    async def write_data(self, reader, writer, filename, data):
     
        data = data.encode()
        chunks = [data[i:i + 1024] for i in range(0, len(data), 1024)]

        if self.set_lock(filename):
            print("Lock Aquired")
            for chunk in chunks:
                chunk_id = self.generate_chunk_id()
                random_peer = self.select_random_peer()
                
                response = requests.get("http://127.0.0.1:5000/chunkNumber?filename={}".format(filename))
                data = response.json()

                chunk_number = data["number"] + 1
                chunk_pieces = []


                if not os.path.exists("./peer_data/{}".format(random_peer)):
                            os.mkdir("./peer_data/{}".format(random_peer))
                            
                chunk_path = "./peer_data/{}/".format(random_peer)
                extension = filename.split(".")[-1]
                
                
                if extension!='exe':
                    with open(chunk_path+str(chunk_id)+'.{}'.format("bin"), 'wb') as output_file:
                        output_file.write(chunk)
                else:
                    with open(chunk_path+str(chunk_id)+'.{}'.format("bin"), 'wb') as output_file:
                        output_file.write(chunk)
                        chunk_number += 1

                chunk_pieces.append({
                    'chunk_peer':random_peer,
                    'chunk_number':chunk_number,
                    'chunk_id': str(chunk_id)
                })
                chunk_number+=1

                print("Stored chunk with id {} in peer {}".format(chunk_id, random_peer))

            response = requests.patch("http://127.0.0.1:5000/addChunkMapping", json={"pieces": chunk_pieces, "filename": filename})
            writer.write("File Updation Succesful".encode())

        else:
            writer.write("Locked aquired by other peer! Please try after some time.".encode())
        
        await writer.drain()

        
    
    def get_private_key_from_database(self, username):
        response= requests.get("http://127.0.0.1:5000/getKey?username={}&type={}".format(username, "private"))
        data = response.json()

        if data["status"] == "Success":
            private_key = data["key"]
            return private_key
        else:
            return False


    def get_private_key_from_db(self, username):
        # Replace this with your actual database retrieval logic
        private_key_pem = self.get_private_key_from_database(username)
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        return private_key
    
    def decrypt_message(self, username, data):
        private_key = self.get_private_key_from_db(username=username)
        decrypted_message = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        data = json.loads(decrypted_message)
        return data

    async def handle_peer(self, reader, writer):
        peer_address = writer.get_extra_info('peername')
        print(f"New connection from {peer_address}")

        try:
            data = await reader.read(1000)
            data = data.decode()
            data = json.loads(data)
            username = data.get("username")
            self.username = username

            self.peers.add(username)
            self.peer_mappings[peer_address] = username
            print(f"Username received: {username}")

            while True:
                data = await reader.read(1000)
                #data = data.decode()
                
                if not data:
                    break

    
                data = self.decrypt_message(self.username, data)
                print('after', data)
                message = data["message"]

                if message == "list_peers":
                    peer_list = ", ".join(str(peer) for peer in self.peers)
                    writer.write(peer_list.encode())
                    await writer.drain()
                
                elif message == "REGISTER_IP":
                    username = data["username"]
                    self.username = username

                    self.peers.add(username)
                    self.peer_mappings[peer_address] = username

                    writer.write("Ip registration successful".encode())
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
                    filename = file_path.split("\\")[-1] if "\\" in file_path else file_path.split("/")[-1]
                    permissions = data.get("permissions")
                    
                    self.add_auth(filename=filename, permissions=permissions)
                    print("Create")
                    receive_file_task = self.receive_file(reader, writer, file_path)
                    await receive_file_task
                
                elif message == "DOWNLOAD":
                    filename = data["filename"]
                    await self.download_file(reader, writer, filename)
                
                elif message == "DELETE":
                    filename = data["filename"]
                    await self.delete_file(reader, writer, filename)
                
                elif message == "RESTORE":
                    filename = data["filename"]
                    await self.restore_file(reader, writer, filename)

                elif message == "WRITE":
                    filename = data['filename']
                    file_data = data['data']

                    await self.write_data(reader, writer, filename, file_data)  
                    writer.write("Sucess".encode())
                    await writer.drain()                  
                else:
                    print(f"Received invalid message from {peer_address}: {message}")

        except Exception as e:
            print(str(e.args))
        finally:
            print("Connection from ({}) closed".format(peer_address))
            #username = self.peer_mappings[peer_address]
            #self.peers.remove(username)

            writer.close()
            await writer.wait_closed()
    
    def select_random_peer(self):
        print(self.peers)
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
    host, port = "127.0.0.1", 8000  # Change the host and port as needed
    asyncio.run(file_server.start_server(host, port))
