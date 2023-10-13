## Introduction

The goal of this project is to create a reliable and safe peer-to-peer (P2P) file storage system that uses a decentralized network for file management and sharing. We will accomplish this by utilizing the Chord Distributed Hash Table (DHT). Data integrity, security, and user-friendliness are guaranteed by the system's extensive feature set, which includes version control, access control, data encryption, and auditing.

## Working and Architecture
Our P2P file storage system operates through a complex mechanism that integrates data integrity, security, and decentralization to give users a reliable platform for managing and storing their files. This is a thorough description of the system's workings:

**<img src="https://drive.google.com/uc?export=view&id=15CsOqNSuAuFOkXQ4rzSegfB2MshRplze" width="25rem" height="30rem" style=""/> 1.Initialization and Node Joining:**

- When a user joins the network, they become part of the Chord DHT, which serves as the foundation of the system.
- The Chord DHT assigns a unique identifier (a Chord key) to each user based on their user ID.
- The user's node joins the network by contacting an existing node and updating the Chord ring structure.
  
**<img src="https://drive.google.com/uc?export=view&id=1mbcpw3-u5NiNNG-ftYOvj-2ZXdWNzkMZ" width="25rem" height="30rem"/> 2.Decentralized File Storage:**

- Users can upload files to the system. When a user uploads a file, it is divided into smaller chunks or blocks.
- Each chunk is associated with a unique key derived from its content using cryptographic hashing.
- These chunks are distributed across the Chord network and stored on appropriate nodes based on their keys.
- Replication mechanisms ensure that data is stored redundantly to enhance fault tolerance.

**<img src="https://drive.google.com/uc?export=view&id=1HQE30_kxIunRRCuqhrLPkrZIRK5afdJG" width="25rem" height="30rem"/>  3.Version Control:**

- The system employs version control to keep track of file changes and maintain a history of file versions.
- When a user makes changes to a file, the system creates a new version, assigns it a unique timestamp or version number, and stores it along with the file's metadata.
- Users can access and restore specific versions of files, promoting data integrity and facilitating collaboration.
  
**<img src="https://drive.google.com/uc?export=view&id=1FDYiDDCrfA-qpKVbEdaH6zkpvRJcp8Th" width="25rem" height="30rem"/> 4.Access Control and Permissions:**

- Users can set access control and permissions on files and directories. These permissions define who can read, write, or delete files.
- Access control lists (ACLs) are maintained for each file or directory, ensuring that only authorized users can access or modify them.
  
**<img src="https://drive.google.com/uc?export=view&id=1I8qEvGw6QFAvllRLaU7jh15N8wvRb0pD" width="25rem" height="30rem"/>    5.Security and Data Privacy:**

- The system takes data privacy and security seriously.
File contents and metadata are encrypted, ensuring that only authorized users can access and understand the data.
- Secure communication protocols protect data in transit, and user authentication mechanisms prevent unauthorized access.
- Auditing and logging track user activities, enhancing security and accountability.
  
**<img src="https://drive.google.com/uc?export=view&id=1d9dmy2xg6LX0ah4Y8i02xpEmQMTvoB_s" width="25rem" height="30rem"/>  6.Concurrent Write and Read Management:**

- To handle concurrent write and read operations, the system implements mechanisms such as file locking and conflict resolution.
- When multiple users attempt to modify the same file simultaneously, the system identifies conflicts and resolves them using predefined strategies.
  
**<img src="https://drive.google.com/uc?export=view&id=1AQpR5Y1ZA2nM5b8Taqiz7tbQEVVLgwnI" width="25rem" height="30rem"/>  7.File Retrieval:**

- When a user requests a specific file, the system uses the Chord DHT to locate the file's chunks based on their keys.
- The system retrieves the chunks from their respective nodes, reassembles the file, and decrypts it if necessary.
  
**<img src="https://drive.google.com/uc?export=view&id=1kxaKZenUP9GKVGIQTx7JIdhXuPlC7RBc" width="25rem" height="30rem"/>  8.Data Redundancy and Availability:**

- To ensure data availability, the system replicates data across multiple nodes in the Chord network.
- This redundancy prevents data loss in case of node failures and improves data availability and fault tolerance.
  
**<img src="https://drive.google.com/uc?export=view&id=1i4shX2XdNv-rw8UHTMYXpXQ1QfofsCWo" width="25rem" height="30rem"/> 9.User-Friendly Interface:**

- The system features a user-friendly interface that allows users to manage their files, view version histories, set permissions, and restore specific file versions.

Our P2P file storage system provides a complete and safe solution for users to store, manage, and retrieve their files in a decentralized network by merging the Chord DHT with sophisticated version control, access control, security measures, and an intuitive user interface. The system is an effective tool for contemporary file management since it places a strong emphasis on data integrity, privacy, and effective teamwork.

## Class Diagrams

<picture>
  <img alt="UML" src="https://drive.google.com/uc?export=view&id=1z0d3SA2_k0UmDwPW3wC7qwc4C5KH0W0o"/>
</picture>

<picture>
    <img alt="UML" src="https://drive.google.com/uc?export=view&id=1cPUCmhZxHgVUumtbo68-FH-pmrGKYqkg">
</picture>

## Architecture Diagram

<picture>
    <img alt="UML" src="https://drive.google.com/uc?export=view&id=1426dniZ2eiWtcSn6BqaXtm19nXn_Hojw">
</picture>


