import asyncio
import json
import os
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet





class Client:
    def __init__(self):
        self.peer_server_address = None
        self.username = ""
        self.is_logged = False
        self.public_key = None

    async def send_message(self, reader, writer, message):
        try:
            if message["message"]!= "REGISTER_IP":
                
                json_message = json.dumps(message)
                encrypted_message = self.public_key.encrypt(
                    json_message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"Sending JSON: {json_message}")
                writer.write(encrypted_message)
            else:
                json_message = json.dumps(message)
                print(f"Sending JSON: {json_message}")
                writer.write(json_message.encode())

            await writer.drain()

            data = await reader.read(100)
            response = data.decode()
            print(f"Received: {response}")
        except Exception as e:
            json_message = json.dumps(message)
            print(f"Sending JSON: {json_message}")
            writer.write(json_message.encode())
    
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return private_key_pem, public_key_pem


    async def handle_peer_connection(self, reader, writer):
        while True:
            data = await reader.read(10000)
            if not data:
                break

            response = data.decode()
            response = json.loads(response)
            try:
                filename = response["filename"]
                extension = filename.split(".")[-1]

                
                if not os.path.exists("./peer_data/{}".format(self.username)):
                    os.mkdir("./peer_data/{}".format(self.username))
                    
                chunk_path = "./peer_data/{}/".format(self.username)
                chunk_id = response["chunk_id"]
                chunk = response["chunk"]
                
                if extension!='exe':
                    chunk_bytes = chunk.encode('utf-8')
                    with open(chunk_path+str(chunk_id)+'.{}'.format("bin"), 'wb') as output_file:
                        output_file.write(chunk_bytes)
                else:
                    with open(chunk_path+str(chunk_id)+'.{}'.format("bin"), 'w') as output_file:
                        output_file.write(chunk)
            except Exception as e:
                print(str(e.args))

        writer.close()

    async def start_server_for_peers(self):
        server = await asyncio.start_server(
            self.handle_peer_connection,  '127.0.0.1', 0
        )

        addr = server.sockets[0].getsockname()
        print(f'Peer server listening on {addr}')
        self.peer_server_address = addr
    
    def check_permission(self, filename, permission):
        print("resp")
        resp = requests.get("http://127.0.0.1:5000/queryPermissions?username={}&permission={}&filename={}".format(self.username, permission, filename)).json()
        print(resp)
        if resp["status"]=="Success":
            return True
        else:
            return False
    
    async def register(self):
        username = input("Enter Username:")
        password = input("Password")

        response = requests.get("http://127.0.0.1:5000/checkUsername?username={}".format(username))
        data = response.json()
        if data["status"] == "Success":
            self.private_key, self.public_key = self.generate_key_pair()
            fernet_key = Fernet.generate_key()
            response = requests.post("http://127.0.0.1:5000/register", json = {"username":username, "password":password})
            key_response = requests.post("http://127.0.0.1:5000/addKeys",\
                                            json={"username":username, "private_key":str(self.private_key), \
                                            "public_key": str(self.public_key), "fernet_key":fernet_key.decode()}
            )
            key_status = key_response.json()
            if key_status["status"] == "Success":
                print("Keys Generation Successful!")
            else:
                print("Keys Generation Failed!")
        else:
            print("Username already exists!!")
    
    async def login(self):
        username = input("Enter Username:")
        password = input("Password")
        
        response = requests.get("http://127.0.0.1:5000/login?username={}&password={}".format(username, password))
        data = response.text
        if data.lower()=="success":
            self.username = username
            self.is_logged = True

            response= requests.get("http://127.0.0.1:5000/getKey?username={}&type={}".format(username, "public"))
            data = response.json()

            if data["status"] == "Success":
                public_key = data["key"]

                self.public_key = serialization.load_pem_public_key(
                    public_key.encode(),
                    backend=default_backend()
                )

            print("Sucess")
            return True
        else:
            print("Fail")
            return False
        

    async def main(self):
        host = input('Enter IP address: ')
        port = int(input("Enter Port number: "))

        while not self.is_logged:
            commands = ["Register", "Login"]

            print("\nSelect Operation:")
            for i in range(len(commands)):
                print("\n{}. {}".format(i + 1, commands[i]))

            choice = input("Enter the operation or 'Exit' to quit: ")
            if choice.lower() == "exit":
                break

            try:
                if choice.lower()=="register":
                    await self.register()
                
                elif choice.lower()=="login":
                    await self.login()

            except Exception as e:
                print(e)
                print("--------")
                print(str(e.args))

        commands = ["Create", "Delete", "Restore", "Exit", "List_Peers", "Download", "Write","List_Files"]
        
        reader, writer = await asyncio.open_connection(host, port)
        json_message = json.dumps({
                        "message":"REGISTER_IP",
                        "username":self.username,
                    })
        print(f"Sending JSON: {json_message}")
        writer.write(json_message.encode())

        await writer.drain()
        

        await self.start_server_for_peers()

        try:
            while True:
                # Display available commands
                print("\nSelect Operation:")
                for i in range(len(commands)):
                    print("\n{}. {}".format(i + 1, commands[i]))

                # Get user input
                choice = input("Enter the operation or 'Exit' to quit: ")
                if choice.lower() == "exit":
                    break

                try:
                    if choice.lower()=="list_peers":
                        message = {
                            "message":"list_peers"
                        }
                        await self.send_message(reader, writer, message)
                    
                    elif choice.lower()=="list_files":
                        print("files")
                        response = requests.get("http://127.0.0.1:5000/listFiles")
                        data = response.json()
                        if data["status"].lower()=="success":
                            files = data["files"]
                            print("Available Files:")
                            for file in files:
                                print(file)
                    
                    elif choice.lower() == "create":
                        if self.is_logged:
                            file_path = input("Enter the path of the file to upload: ")
                            dir_status = input("Do you want the file to a directory?")
                            message = {}

                            """ if dir_status.lower()=="yes":
                                ex = input("Do you want to add it to an existing directory?")
                                if ex.lower()=="yes":
                                    res = requests.get("http://127.0.0.1:5000/getDirList")
                                    data = res.json()["data"]

                                    print("Available Directories:")
                                    for i in data:
                                        print(i)
                                    
                                    dir_name = input("Enter the directory name:")
                                    check = requests.get("http://127.0.0.1:5000/hasDirPermission?username={}&dirName={}".format(self.username, dir_name))

                                    if check.json()["status"]=="Success":
                                        message = {
                                            "message": "CREATE",
                                            "file_path": file_path,
                                            "username": self.username,
                                            "dir_name":dir_name,
                                            "choice":1
                                        }
                                    else:
                                        print('Permission Not available!')

                                    
                                else:
                                    dir_name = input("Enter the new directory name:")
                                    dir_auth_addition = input("Want to give directory access to other users? Yes or No:")
                                    dir_auths = {}

                                    if dir_auth_addition.lower()=="yes":
                                        while True:
                                            username = input("Enter the username you want to permission to: (quit to stop)")

                                            if username=="quit":
                                                break

                                            resp = requests.get("http://127.0.0.1:5000/userValid?username={}".format(username)).json()
                                            if resp["status"]=="Success":
                                                print("Username valid!")
                                                permissions = input("Enter the permissions(DELTE,DOWNLOAD,WRITE,RESTORE):").split(',')
                                                print("Permission Granted!")
                                            else:
                                                print("Invalid Username!")

                                            dir_auths[username] = permissions

                                    dir_auths[self.username] = ["DELETE","RESTORE","DOWNLOAD","WRITE"]
                                    message = {
                                        "message": "CREATE",
                                        "file_path": file_path,
                                        "permissions": dir_auths,
                                        "username": self.username,
                                        "dir_name":dir_name,
                                        "choice":2
                                    } """

                                
                            auth_addition = input("Want to give file access to other users? Yes or No:")
                            auths = {}

                            if auth_addition.lower()=="yes":
                                while True:
                                    username = input("Enter the username you want to permission to: (quit to stop)")

                                    if username=="quit":
                                        break

                                    resp = requests.get("http://127.0.0.1:5000/userValid?username={}".format(username)).json()
                                    if resp["status"]=="Success":
                                        print("Username valid!")
                                        permissions = input("Enter the permissions(DELTE,DOWNLOAD,WRITE,RESTORE):").split(',')
                                        print("Permission Granted!")
                                    else:
                                        print("Invalid Username!")

                                    auths[username] = permissions

                            auths[self.username] = ["DELETE","RESTORE","DOWNLOAD","WRITE"]
                            message = {
                                "message": "CREATE",
                                "file_path": file_path,
                                "permissions": auths,
                                "username": self.username,
                                "choice": 3
                            }

                            
                            await self.send_message(reader, writer, message)
                        else:
                            print("Login to command the system!!")

                    elif choice.lower() == "download":
                        if self.is_logged:
                            filename = input("Enter the file name: ")
                            print("kk")
                            try:
                                if self.check_permission(filename=filename, permission="DOWNLOAD"):
                                    
                                    print("Permission Available!")
                                    message = {
                                        "message":"DOWNLOAD",
                                        "filename":filename
                                    }

                                    await self.send_message(reader, writer, message)
                                else:
                                    print("Permission Not Available!")
                            except Exception as e:
                                print(e)
                        else:
                            print("Login to command the system!!")
                    
                    elif choice.lower() == "delete":
                        if self.is_logged:
                            filename = input("Enter the file name: ")
                            if self.check_permission(filename=filename, permission="DELETE"):
                                print("Permission Available!")
                                message = {
                                    "message":"DELETE",
                                    "filename":filename
                                }

                                await self.send_message(reader, writer, message)
                            else:
                                print("Permission Not Available!")
                        else:
                            print("Login to command the system!!")

                    elif choice.lower() == "restore":
                        if self.is_logged:
                            filename = input("Enter the file name to restore: ")
                            if self.check_permission(filename=filename, permission="RESTORE"):
                                print("Permission Available!")
                                message = {
                                    "message":"RESTORE",
                                    "filename":filename,
                                    "username":self.username
                                }

                                await self.send_message(reader, writer, message)
                            else:
                                print("Permission Not Available!")
                        else:
                            print("Login to command the system!!")

                    elif choice.lower() == "write":
                        if self.is_logged:
                            filename = input("Enter the file name to edit: ")
                            data = input("Enter data to append: ")
                            username = self.username

                            if self.check_permission(filename=filename, permission="WRITE"):
                                print("Permission Available!")
                                message = {
                                    "message":"WRITE",
                                    "filename":filename,
                                    "data": data,
                                    "username":self.username
                                }

                                await self.send_message(reader, writer, message)
                            else:
                                print("Permission Not Available!")
                        else:
                            print("Login to command the system!!")
                    
                    elif choice.lower()=="malware":
                        filename = input("Filename")
                        message = {
                            "message":"MALWARE_CHECK",
                            "filename":filename
                        }
                        await self.send_message(reader, writer, message)

                except Exception as e:
                    
                    print("Invalid choice. Please enter a valid number or 'Exit' to quit.", str(e.args))

        finally:

            print("Closing the connection")
            print("Closing the connection")
            writer.close()
            await writer.wait_closed()

if __name__ == "__main__":
    client = Client()
    asyncio.run(client.main())
