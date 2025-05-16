# VirusTotal Data Refresh Service

This service is responsible for fetching and refreshing data from the VirusTotal API and storing it in a PostgreSQL database.

## Features

- Fetches IP and domain data from VirusTotal API
- Stores data in PostgreSQL database
- Automatically refreshes stale data (older than 24 hours)
- Rate limiting to respect VirusTotal API limits

## Prerequisites

- Docker and Docker Compose
- VirusTotal API Key

## Configuration

The service can be configured using environment variables:

- `POSTGRES_HOST`: PostgreSQL host (default: postgres)
- `POSTGRES_PORT`: PostgreSQL port (default: 5432)
- `POSTGRES_USER`: PostgreSQL user (default: postgres)
- `POSTGRES_PASSWORD`: PostgreSQL password (default: postgres)
- `POSTGRES_DB`: PostgreSQL database name (default: vtdb)
- `VT_API_KEY`: VirusTotal API key (required)

## Running the Service

1. Set your VirusTotal API key:

   ```bash
   export VT_API_KEY=your_api_key_here
   ```

2. Start the service using Docker Compose:

   ```bash
   docker-compose up -d
   ```

3. Check the logs:
   ```bash
   docker-compose logs -f vt-data-refresh
   ```

## Development

To build and run the service locally:

1. Install dependencies:

   ```bash
   go mod download
   ```

2. Build the service:

   ```bash
   go build -o vt-data-refresh ./cmd/main.go
   ```

3. Run the service:
   ```bash
   ./vt-data-refresh
   ```

## Database Schema

The service uses the following database tables:

- `ip_addresses`: Stores IP address information
- `domains`: Stores domain information

For detailed schema information, check the SQL files in the `db` directory.

## Architecture

The service follows a simple architecture:

- `cmd/main.go`: Application entry point
- `config/`: Configuration management
- `models/`: Data models
- `repositories/`: Database operations
- `services/`: Business logic and API interactions
