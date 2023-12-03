## Introduction

This project aims to create a reliable and safe peer-to-peer (P2P) file storage system that uses a decentralized network for file management and sharing. We will accomplish this by utilizing a central tracking server. Data integrity, security, and user-friendliness are guaranteed by the system's extensive feature set, which includes access control, data encryption, and auditing.

## Working and Architecture
Our P2P file storage system operates through a complex mechanism that integrates data integrity, security, and decentralization to give users a reliable platform for managing and storing their files. This is a thorough description of the system's workings:

**<img src="https://drive.google.com/uc?export=view&id=15CsOqNSuAuFOkXQ4rzSegfB2MshRplze" width="25rem" height="30rem" style=""/> 1.Initialization and Node Joining:**

- When a user joins the network, they become part of the central tracking server, which serves as the foundation of the system.
- The tracking server assigns a unique user ID to each user. If the user id is the same it won't register.
  
**<img src="https://drive.google.com/uc?export=view&id=1mbcpw3-u5NiNNG-ftYOvj-2ZXdWNzkMZ" width="25rem" height="30rem"/> 2.Decentralized File Storage:**

- Users can upload files to the system. When a user uploads a file, it is divided into smaller chunks or blocks.
- Each chunk is associated with a unique key derived from its content using cryptographic hashing.
- These chunks are distributed across the network and stored on appropriate nodes based on their keys.
    
**<img src="https://drive.google.com/uc?export=view&id=1FDYiDDCrfA-qpKVbEdaH6zkpvRJcp8Th" width="25rem" height="30rem"/> 3.Access Control and Permissions:**

- Users can set access control and permissions on files and directories. These permissions define who can read, write, delete, or download files.
- Access control lists (ACLs) are maintained for each file or directory, ensuring that only authorized users can access or modify them.
  
**<img src="https://drive.google.com/uc?export=view&id=1I8qEvGw6QFAvllRLaU7jh15N8wvRb0pD" width="25rem" height="30rem"/> 4.Security and Data Privacy:**

- The system takes data privacy and security seriously.
- File contents and metadata are encrypted, ensuring only authorized users can access and understand the data.
- Secure communication protocols protect data in transit, and user authentication mechanisms prevent unauthorized access.
- Auditing and logging track user activities, enhancing security and accountability.
  
**<img src="https://drive.google.com/uc?export=view&id=1d9dmy2xg6LX0ah4Y8i02xpEmQMTvoB_s" width="25rem" height="30rem"/> 5.Concurrent Write and Read Management:**

- To handle concurrent write and read operations, the system implements mechanisms such as file locking and conflict resolution.
- When multiple users attempt to modify the same file simultaneously, the system identifies conflicts and resolves them using predefined strategies.
  
**<img src="https://drive.google.com/uc?export=view&id=1AQpR5Y1ZA2nM5b8Taqiz7tbQEVVLgwnI" width="25rem" height="30rem"/>  6.File Retrieval:**

- When a user requests a specific file, the system uses the Flask Server (MetaData Server) to locate the file's chunks based on their keys.
- The system retrieves the chunks from their respective nodes, reassembles the file, and decrypts it if necessary.
    
## Class Diagrams

<picture>
  <img alt="UML" src="https://drive.google.com/uc?export=view&id=1z0d3SA2_k0UmDwPW3wC7qwc4C5KH0W0o"/>
</picture>

<picture>
    <img alt="UML" src="https://drive.google.com/uc?export=view&id=1cPUCmhZxHgVUumtbo68-FH-pmrGKYqkg">
</picture>

## Architecture Diagram

<picture>
    <img alt="UML" src="https://drive.google.com/file/d/1g1RdIFGKHmaKFQECVq6BxvNNYl_XjCcf/view?usp=sharing">
</picture>


