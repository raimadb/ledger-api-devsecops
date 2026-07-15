# ledger-api

Payments microservice for tokenising PANs and serving transaction metadata.
Deployed on Kubernetes in the `payments` namespace.

## Endpoints

| Method | Path            | Description                          |
|--------|-----------------|--------------------------------------|
| GET    | `/health`       | Liveness check                       |
| POST   | `/tokenize`     | `{"pan": "..."}` → opaque token      |
| GET    | `/transactions` | Recent transaction records           |
| POST   | `/import`       | Import a YAML configuration blob     |
| GET    | `/fetch?url=`   | Fetch a remote resource by URL       |
