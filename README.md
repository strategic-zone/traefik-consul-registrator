# Traefik-Consul-Registrator

A lightweight service that automatically registers Traefik-exposed Docker containers in Consul.

## Overview

Traefik-Consul-Registrator bridges the gap between Traefik and Consul by automatically registering Docker containers that are exposed through Traefik into Consul's service catalog. This enables service discovery and health monitoring for your containerized applications.

## Features

- Selective registration of Docker containers in Consul using `traefik.consul.expose = true` label
- Container event monitoring (start, stop, kill)
- Periodic synchronization to maintain consistency
- Customizable service tags based on Traefik labels
- Support for Traefik v2 label format
- Flexible network selection with priority options
- Optional cleanup of stale services
- Configurable through command-line flags or environment variables

## Installation

### Using Docker

```bash
docker run -d --name traefik-consul-registrator \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --network=host \
  ghcr.io/strategic-zone/traefik-consul-registrator:latest \
  --consul-api=http://localhost:8500
```

### Using Docker Compose

Check the `compose.yml` file in the repository for an example setup.

## Configuration

### Command-line Options

| Flag | Description | Default |
|------|-------------|--------|
| `--consul-api` | Consul API URL | http://127.0.0.1:8500 |
| `--sync-interval` | Interval in seconds between sync operations | 60 |
| `--internal` | Use internal container ports instead of published ones | false |
| `--cleanup` | Clean up stale services on startup | false |
| `--networks-priority` | Prioritize networks by name or subnet (comma-separated) | "" |
| `--tags` | Default tags to apply to all services (comma-separated) | "" |
| `--deregister` | When to deregister containers: 'always' or 'on-success' | always |
| `--host-ip` | Host IP address to use for service registration | auto-detected |
| `--version` | Show version information | |

### Environment Variables

All command-line options can also be configured through environment variables with the `TCR_` prefix (e.g., `TCR_CONSUL_API`). Environment variables are used as fallbacks when command-line options are not specified.

## How It Works

Traefik-Consul-Registrator performs the following operations:

1. Connects to both Docker and Consul on startup
2. Monitors Docker events (container start/stop/kill)
3. Identifies containers with the `traefik.consul.expose = true` label
4. Extracts service information from Traefik labels
5. Registers services in Consul with appropriate health checks
6. Periodically synchronizes containers with Consul
7. Deregisters services when containers stop or are removed

## Service Registration

### Required Labels

To register a container in Consul, it must have the following label:

```
traefik.consul.expose=true
```

Only containers with this label will be registered, regardless of other Traefik labels.

### Service Details

For each qualifying container, the registrator creates a Consul service with:

- ID: `<container-id>-<port>`
- Name: Derived from service labels or container name
- Address: Container IP or host IP (depending on network mode)
- Port: Container exposed port
- Tags: Generated from Traefik labels (including domain, entrypoints, etc.)

## Examples

### Basic Docker Container

```bash
docker run -d --name my-service \
  -l "traefik.enable=true" \
  -l "traefik.consul.expose=true" \
  -l "traefik.http.routers.my-service.rule=Host(\`my-service.example.com\`)" \
  -l "traefik.http.services.my-service.loadbalancer.server.port=80" \
  my-image:latest
```

This will be registered in Consul as service `my-service` with tags including `domain:my-service.example.com`.

### Container Not Registered in Consul

```bash
docker run -d --name my-other-service \
  -l "traefik.enable=true" \
  -l "traefik.http.routers.my-other-service.rule=Host(\`other.example.com\`)" \
  -l "traefik.http.services.my-other-service.loadbalancer.server.port=80" \
  my-image:latest
```

This container will be handled by Traefik but NOT registered in Consul because it lacks the `traefik.consul.expose=true` label.

## License

MIT License
