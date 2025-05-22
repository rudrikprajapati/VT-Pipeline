# 🔍 VirusTotal Data Pipeline

A Dockerized Go-based microservice pipeline that fetches and serves domain and IP reports from the [VirusTotal API](https://developers.virustotal.com/reference). It features RESTful services, PostgreSQL for persistence, Redis for caching and rate-limiting, and PGAdmin for database management.

---

## 🧰 Tech Stack

- **Go** – REST APIs for fetching and serving VirusTotal reports
- **PostgreSQL** – Structured data storage
- **Redis** – Caching and rate-limiting
- **Docker Compose** – Container orchestration
- **PGAdmin** – GUI for managing PostgreSQL
- **RedisInsight** – GUI for inspecting Redis

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd <project-directory>
```

---

### 2. Set Up Environment Variables

Create `.env` files for both services.

- **vt-data-api/.env**:

```env
VT_API_KEY=7c155eaab2d47e2d5df8b0ee25a5c80647bd30e37ab37c43adb635b0cd6720a9
DB_URL=postgresql://vt_data_pipeline:vt_data_pipeline_password@localhost:5432/vt_data_pipeline?sslmode=disable
PORT=8080
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=
```

- **vt-data-refresh/.env**:

```env
VT_API_KEY=7c155eaab2d47e2d5df8b0ee25a5c80647bd30e37ab37c43adb635b0cd6720a9
DB_URL=postgresql://vt_data_pipeline:vt_data_pipeline_password@localhost:5432/vt_data_pipeline?sslmode=disable
PORT=8081
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=
```

---

### 3. Launch with Docker Compose

From the project root:

```bash
docker compose build && docker compose up -d ⁠
```

This launches:

- `vt-data-api` at `http://localhost:8080`
- `vt-data-refresh` at `http://localhost:8081`
- `PostgreSQL` at `localhost:5432`
- `Redis` at `localhost:6379`
- `PGAdmin` at `http://localhost:5050`
- `RedisInsight` at `http://localhost:8001`

---

### 4. Verify Services

Check containers:

```bash
docker ps
```

---

## 🧑‍💻 PGAdmin Setup

1. Go to [http://localhost:5050](http://localhost:5050)
2. Login:

   - Email: `admin@admin.com`
   - Password: `admin`

3. Register a new server:

   - **General**: Name = `vt-data-pipeline`
   - **Connection**:

     - Host: `postgres`
     - Port: `5432`
     - Database: `vt_data_pipeline`
     - Username: `vt_data_pipeline`
     - Password: `vt_data_pipeline_password`

---

## 🗄️ Create Database Tables

Copy paste SQL : Use PGAdmin client to create tables:

`vt-data-api/db/domain.sql`
`vt-data-api/db/ip.sql`

---

## 🔁 Refresh Data from VirusTotal

Trigger report fetch via `vt-data-refresh`:

- **Domain:**

```bash
curl "http://localhost:8081/refresh/domains"
```

- **IP Address:**

```bash
curl "http://localhost:8081/refresh/ips"
```

---

## 📡 Get Stored Reports

Use `vt-data-api` to retrieve cached/stored reports:

- **Domain:**

```bash
curl "http://localhost:8080/report/example.com?type=domains"
```

- **IP Address:**

```bash
curl "http://localhost:8080/report/8.8.8.8?type=ip_addresses"
```

---

## 🧹 Clean Up And Restart

```bash
docker compose down && docker compose build && docker compose up -d ⁠
```
