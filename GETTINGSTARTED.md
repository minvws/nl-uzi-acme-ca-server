# Getting started

## Requirements
To run the server locally, make sure you have `docker` installed and the `openssl` tool to generate a root certificate.

## Generate a CA root certificate
The first step is to generate a root certificate and a private key. Use the command below to generate these in the root of the project.

```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -nodes -days 3650 -subj "/C=DE/O=Demo" -key ca.key -out ca.pem
```

## Start the server
Then, use docker compose to build the image and start the process.

`docker compose up --build`