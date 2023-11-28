# CentralConnect: Unified Credential Management

**CentralConnect**  is a specialized module crafted to complement the DataMiner package, aiming to centralize and secure the management of credentials and database connections. As a core component, it enables seamless interactions across various databases and network infrastructures. CentralConnect adopts a centralized framework, streamlining the sharing of credentials in parallel or grid-based architectures. This proves particularly beneficial when deploying updated instructions across multiple servers, allowing them to leverage a unified, encrypted PostgreSQL 15+ database. This database efficiently handles host configurations and API key management, making CentralConnect an invaluable tool in simplifying and securing large-scale server operations.

## Features

- **Unified Credential Access**: CentralConnect simplifies the management of credentials, ensuring secure access across different systems.
- **Database Connectivity**: Offers robust functionalities for querying databases, particularly PostgreSQL, via the psycopg2 driver.
- **Network Management**: Includes tools for pinging hosts and managing network information, making it versatile for both GUI and CLI interfaces.
- **Encryption and Decryption**: Ensures the security of credentials by providing encryption and decryption capabilities.

## Installation

To install CentralConnect, follow these steps:

1. Ensure you have Python installed on your system.
2. Download the CentralConnect module from [source].
3. Install any required dependencies (e.g., psycopg2 for PostgreSQL interaction).
4. Include the CentralConnect module in your Python project.

## Usage

Here's a simple example to get started with CentralConnect:

\```python
from CentralConnect import Server, Credential

server = Server()
available_hosts = server.ping_hosts()
credentials = Credential('my_database')
decrypted_credential = credentials.get_decrypted()
\```

This example demonstrates basic operations like pinging hosts and managing database credentials.

## Contributing

Contributions are welcome! If you're interested in improving CentralConnect, please:

1. Fork the repository.
2. Make your changes in a dedicated branch.
3. Submit a pull request with a detailed description of your improvements.

## License

CentralConnect is licensed under the MIT License. You are free to use, modify, and distribute it as per the license terms.
