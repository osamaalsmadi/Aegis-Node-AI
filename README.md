# Aegis-Node-AI

A Windows endpoint security portfolio project combining a .NET agent, an ASP.NET Core API, and a React dashboard.

**C# · .NET 10 · React · TypeScript · SQL Server · Entity Framework Core · Ollama integration**

## Project areas

| Component | Purpose |
| --- | --- |
| [Agent](src/EndpointSecurity.Agent) | Windows endpoint telemetry and background workers |
| [API](src/EndpointSecurity.Api) | Devices, findings, security events, and reporting endpoints |
| [Dashboard](src/EndpointSecurity.Dashboard) | Endpoint and security-management interface |
| [Application](src/EndpointSecurity.Application) | Service contracts |
| [Domain](src/EndpointSecurity.Domain) | Entities and enums |
| [Infrastructure](src/EndpointSecurity.Infrastructure) | SQL Server persistence and services |
| [Scripts](scripts) | Local installation and service-management utilities |

## Prerequisites

- .NET 10 SDK for the API and agent projects.
- Node.js/npm compatible with the frontend package and lockfile.
- A reachable SQL Server database with a valid connection string.
- Windows for Windows-specific agent functionality.
- A local Ollama service for features that depend on that integration.

## Development setup

Review configuration before starting. Provide the database connection through `ConnectionStrings__EndpointSecurityDatabase`; keep credentials outside committed files. The API applies database migrations at startup, so use a dedicated development database.

From the repository root:

```sh
dotnet run --project src/EndpointSecurity.Api
```

The API defaults to http://127.0.0.1:5235. In a second terminal:

```sh
cd src/EndpointSecurity.Dashboard
npm ci
npm run dev
```

Open http://127.0.0.1:5173. The Vite configuration proxies `/api` to port 5235.

Ollama defaults to http://127.0.0.1:11434. The API requires the configured Ollama address to be loopback. Review installation scripts before running them: they may install or update Windows services.

## Build

```sh
dotnet build EndpointSecurityPlatform.slnx
cd src/EndpointSecurity.Dashboard
npm run build
```

A full Windows agent/API/database integration run has not been verified in this documentation review.

## Screenshots

<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/638c16cc-8ee4-4938-b6b0-b1718f93dc6f" />

<details>
<summary>View more dashboard screenshots</summary>


<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/ceadc7e8-196b-420e-bc73-509155f0c279" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/685c872b-f0ab-4cf3-92b3-53d7417ad3b5" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/d27b94b3-f24f-441a-905d-9be10365a2f0" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/fc99373e-6914-410f-a7c6-4c10e513f94f" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/98d3985d-01fc-41fd-8ed6-4cc1851bedc3" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/347709cd-abdd-46dc-a95f-a533a5dad545" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/aafa2db0-38c1-46e6-abb9-049b00f28fdf" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/d9496533-c1ea-4dd9-8f35-0bd99366f5d1" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/83709133-2ad6-4757-aea5-a1bac1d95003" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/07da5e70-1983-42bd-98f6-ede403e0769b" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/24364d46-7568-4d15-8925-4d4602ecf224" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/c1bcc6c0-97ad-452a-ab29-77c31cc5dfcf" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/a138928d-ec55-4eaa-8793-17714a92bc84" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/f19a1159-d38c-4ba0-8377-848ac05233d7" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/a40a8f4f-adbe-4f13-a376-83e5d585dfe6" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/c1131f7f-fe10-4ffa-9937-f52d59a8dbe3" />
<img width="100%" alt="Aegis-Node-AI dashboard screenshot" src="https://github.com/user-attachments/assets/aee4b38c-7de7-4f4b-8095-e4d0e0bb6dd2" />

</details>

## Scope

This repository demonstrates endpoint security engineering concepts. Detection efficacy, production hardening, and operational reliability require dedicated testing; the presence of AI-related modules is not a guarantee of threat prevention.
