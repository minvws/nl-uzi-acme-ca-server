# Local setup
This document will explain the process to run the ACME CA server locally. First, To run the ACME CA server locally. Initial system requirements are to have the following tools available in your terminal.
- **`python3.13`**: Make sure the executable is also accessible from your local terminal. 
- **`docker`**: Together with Docker Desktop to easily debog container information.
- **`git`**: To update the application when needed.

## Getting started

### 1. Generate a root certificate and a private key
To issue certificates, we need a root certificate and the corresponding private key. These can be generated with the underneath commands.

```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -nodes -days 3650 -subj "/C=DE/O=Demo" -key ca.key -out ca.pem
```

## 2. Starting up
The application is hosted in a Docker container and published on port `8080`. To start, run the underneath command.
```bash

docker compose up --build
```