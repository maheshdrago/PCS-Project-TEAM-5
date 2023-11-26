import asyncio
import json

async def send_message(reader, writer, message):
    json_message = json.dumps(message)
    print(f"Sending JSON: {json_message}")
    writer.write(json_message.encode())

    await writer.drain()

    data = await reader.read(100)
    response = data.decode()
    print(f"Received: {response}")

async def main():
    host = input('Enter IP address: ')
    port = int(input("Enter Port number: "))

    commands = ["Register", "Login", "Create", "Delete", "Restore", "Exit", "List_Peers", "Download"]
    reader, writer = await asyncio.open_connection(host, port)

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
                if choice.lower()=="register":
                    username = input("Enter Username:")
                    password = input("Password")

                    message = {
                        "message": "REGISTER",
                        "username": username,
                        "password": password
                    }

                    await send_message(reader, writer, message)
                
                elif choice.lower()=="login":
                    username = input("Enter Username:")
                    password = input("Password")
                    
                    message = {
                        "message": "LOGIN",
                        "username": username,
                        "password": password
                    }

                    await send_message(reader, writer, message)

                elif choice.lower()=="list_peers":
                    message = {
                        "message":"list_peers"
                    }
                    await send_message(reader, writer, message)
                
                elif choice.lower() == "create":
                    file_path = input("Enter the path of the file to upload: ")
                    message = {
                        "message": "CREATE",
                        "file_path": file_path
                    }
                    await send_message(reader, writer, message)

                elif choice.lower() == "download":
                    filename = input("Enter the file name: ")
                    message = {
                        "message":"DOWNLOAD",
                        "filename":filename
                    }

                    await send_message(reader, writer, message)
                
                elif choice.lower() == "delete":
                    filename = input("Enter the file name: ")
                    message = {
                        "message":"DELETE",
                        "filename":filename
                    }

                    await send_message(reader, writer, message)

            except (ValueError, IndexError):
                print("Invalid choice. Please enter a valid number or 'Exit' to quit.")

    finally:
        print("Closing the connection")
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
