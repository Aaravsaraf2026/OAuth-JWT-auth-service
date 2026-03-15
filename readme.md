# Secure Auth Service

A **production-style authentication backend** built with **FastAPI, PostgreSQL, Redis, and Docker**.
This service provides **secure user authentication using Google OAuth and JWT tokens**, with Redis support for token management and caching.

---

## Overview

This project demonstrates how to build a **secure authentication system** similar to those used in modern backend architectures.

Key capabilities include:

* Google OAuth login
* JWT access and refresh token generation
* Redis integration for token management
* PostgreSQL database storage
* Dockerized multi-service backend
* FastAPI-based API service
# OAuth JWT Auth Service

## Features
- Google OAuth login
- JWT access/refresh tokens
- Redis token store
- PostgreSQL database
- Dockerized backend

## Architecture
(diagram)

## Run
docker compose up --build

## API
/auth/login
/auth/callback
/dashboard
The system is designed with **security, modular architecture, and containerized deployment** in mind.

---

## Tech Stack

**Backend**

* FastAPI
* Python 3.11

**Authentication**

* Google OAuth
* JWT (JSON Web Tokens)

**Database**

* PostgreSQL
* SQLAlchemy
* Psycopg3

**Caching / Token Control**

* Redis

**Infrastructure**

* Docker
* Docker Compose

---

## Architecture

Client requests pass through the API service, which interacts with authentication providers and storage layers.

```
Client
   │
   ▼
FastAPI Application
   │
   ├── Google OAuth
   ├── JWT Token Engine
   │
   ├── PostgreSQL (User Data)
   └── Redis (Token management / caching)
```

---

## Features

* Secure Google OAuth login
* Access token and refresh token generation
* Redis-backed token management
* Automatic database schema initialization
* Structured logging
* Dockerized environment for consistent deployment

---

## Environment Configuration

Create a `.env` file and configure the following variables:

```
DATABASE_URL=postgresql+psycopg://postgres:password@db:5432/db

REDIS_HOST=redis
REDIS_PORT=6379

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
```

---

## Running the Project

### Build and start services

```
docker compose up --build
```

### Run in background

```
docker compose up -d
```

---

## Services

The system runs three containers:

| Service     | Purpose                      |
| ----------- | ---------------------------- |
| FastAPI App | API server                   |
| PostgreSQL  | User database                |
| Redis       | Token management and caching |

---

## API Access

After starting the system, the API will be available at:

```
http://localhost:8000
```

Swagger documentation:

```
http://localhost:8000/docs
```

---

## Authentication Flow

1. User requests login
2. Redirect to Google OAuth
3. Google returns user identity
4. Backend verifies the user
5. JWT tokens are generated
6. User is redirected to the dashboard

---

## Project Structure

```
app/
 ├── main.py
 ├── routes/
 ├── database/
 ├── repo/
 │    ├── auth/
 │    └── jwt/
 └── models/
```

---

## Development Mode

For local development, Redis fallback or in-memory stores may be used.

Production deployments should always enable Redis for token management.

---

## Future Improvements

Potential extensions:

* Role-based access control
* Token revocation lists
* Rate limiting
* Monitoring and metrics
* OAuth providers beyond Google

---

## License

This project is intended for **learning and backend architecture practice**.
