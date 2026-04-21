# Logs Drain Normalization API

This service provides an API for retrieving logs from VictoriaLogs and normalizing them using the Drain algorithm. It is written in Go and supports dynamic querying by service, project, and time ranges.

## Requirements
- Go 1.20+
- VictoriaLogs accessible from the host running the API.

## Running the API
From the root directory (`d:\project\logs-drain`), initialize the dependencies (if any) and run the server:
```bash
go build -o logs-drain
./logs-drain -port 8080
```

## Endpoint

### `POST /api/v1/normalize`

Normalize logs based on specified filters.

**Request Body (JSON):**
```json
{
  "service": "my-service",        // Optional: filter logs by _stream:{service="my-service"}
  "project": "my-project",        // Optional: filter logs by _stream:{project="my-project"}
  "start_time": "2023-10-20T00:00:00Z", // Optional: absolute Start time
  "end_time": "2023-10-21T00:00:00Z",   // Optional: absolute End time
  "victorialogs_url": "http://localhost:9428" // Optional: specify VictoriaLogs instance
}
```

*Note on Time Filtering:*
- If both `start_time` and `end_time` are omitted, the API will default to **processing the entire previous day**.
- `start_time` and `end_time` support any valid VictoriaLogs `_time:` format (e.g. `2023-11-01Z`, timestamps, etc.)

**Response (JSON):**
```json
{
  "total_processed": 1500,
  "templates": [
    {
      "id": "1",
      "template": "User <*> logged in from IP <*>",
      "count": 1200
    },
    {
      "id": "2",
      "template": "Failed authentication attempt for user <*>",
      "count": 300
    }
  ]
}
```

## Architecture
- **API (main.go):** Parses requests, queries VictoriaLogs via `POST /select/logsql/query`, streams the JSON lines, and extracts the `_msg` field.
- **Drain (drain/drain.go):** Ported Drain algorithm logic. It maps similar logs into templates, masking dynamically matched tokens like IP addresses, numbers, and UUIDs with `<*>`.
