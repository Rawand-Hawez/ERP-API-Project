# 🚀 ERP API - Powered by Bun

A modern, fast ERP API built with Bun runtime, Express.js, and TypeScript.

## ✨ Features

- 🥟 **Bun Runtime** - Ultra-fast JavaScript runtime
- 🚀 **Single Service Architecture** - Simplified deployment
- 🔐 **JWT Authentication** - Secure token-based auth
- 📊 **Financial Data API** - Dynamics 365 integration
- 🏢 **Subsidiary Management** - Multi-entity support
- 🛡️ **Security First** - Helmet, CORS, rate limiting
- 🐳 **Docker Ready** - Optimized container deployment

## 🚀 Quick Start

### Prerequisites

- [Bun](https://bun.sh) installed
- Docker and Docker Compose (for container deployment)

### Local Development

1. **Install dependencies**
   ```bash
   bun install
   ```

2. **Set environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start development server**
   ```bash
   bun run dev
   ```

The API will be available at `http://localhost:3080`

### Docker Deployment

1. **Build and run with Docker Compose**
   ```bash
   docker-compose up --build
   ```

2. **Or build and run manually**
   ```bash
   docker build -t erp-api .
   docker run -p 3080:3080 --env-file .env erp-api
   ```

## 📡 API Endpoints

### Public Endpoints

- `GET /` - API information and documentation
- `GET /health` - Health check
- `GET /test` - Test endpoint
- `POST /api/auth/login` - User authentication

### Authenticated Endpoints

All authenticated endpoints require a valid JWT token in the `Authorization` header.

#### Authentication & Tokens
- `GET /api/token` - Get Dynamics 365 access token (admin/finance)

#### Subsidiaries (admin/finance)
- `GET /api/subsidiaries` - Get all subsidiaries
- `GET /api/subsidiaries/:code` - Get subsidiary by code
- `GET /api/operating-units` - Get all operating units
- `GET /api/operating-units/:type` - Get operating units by type

#### Financial Data (authenticated)
- `GET /api/financial/:subsidiary/:year/:month` - Get financial data
- `GET /api/financial/:subsidiary/:year/:month/pl` - Get P&L data

Query parameters for financial endpoints:
- `profitCenter` - Filter by profit center code
- `exchangeRate` - Custom exchange rate (default: 1400)

## 🔐 Authentication

### Default Users

| Username | Password | Role | Access |
|----------|----------|------|--------|
| admin | admin123 | admin | All subsidiaries |
| finance | finance123 | finance | KRD, KRDSUB1 |
| readonly | readonly123 | readonly | KRD |

### Login Example

```bash
curl -X POST http://localhost:3080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "username": "admin",
    "role": "admin",
    "subsidiaries": ["*"]
  }
}
```

### Using the Token

```bash
curl -X GET http://localhost:3080/api/subsidiaries \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## ⚙️ Environment Variables

Create a `.env` file with the following variables:

```bash
# Application
NODE_ENV=production
PORT=3080

# Security
JWT_SECRET=your-super-secret-jwt-key-change-in-production
ENCRYPTION_KEY=your-encryption-key

# Dynamics 365 Configuration
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
DYNAMICS_BASE_URL=https://your-dynamics-instance.operations.eu.dynamics.com

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://api.yourdomain.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

## 🐳 Docker Deployment

### Production Docker Compose

```yaml
version: '3.8'

services:
  erp-api:
    build: .
    ports:
      - "3080:3080"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - TENANT_ID=${TENANT_ID}
      - CLIENT_ID=${CLIENT_ID}
      - CLIENT_SECRET=${CLIENT_SECRET}
      - DYNAMICS_BASE_URL=${DYNAMICS_BASE_URL}
      - ALLOWED_ORIGINS=${ALLOWED_ORIGINS}
    restart: unless-stopped
```

### Coolify Deployment

1. Push your code to a Git repository
2. In Coolify, create a new project
3. Select Docker Compose deployment
4. Configure environment variables
5. Deploy!

## 🛠️ Development

### Scripts

- `bun run dev` - Start development server with hot reload
- `bun run start` - Start production server
- `bun run build` - Build for production
- `bun run test` - Run tests

### Project Structure

```
ERP/
├── src/
│   └── index.ts          # Main application file
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose configuration
├── package.json          # Dependencies and scripts
├── bun.lockb            # Bun lock file
└── README.md             # This file
```

## 🔧 Security Features

- ✅ JWT token authentication
- ✅ Role-based access control (admin/finance/readonly)
- ✅ Subsidiary-level access control
- ✅ Rate limiting
- ✅ CORS protection
- ✅ Security headers (Helmet)
- ✅ Input validation with Zod

## 📈 Performance

- **Bun Runtime**: 3x faster startup than Node.js
- **Single Service**: No inter-service communication overhead
- **Native TypeScript**: No compilation step in production
- **Optimized Docker**: Minimal image size

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions, please open an issue in the repository.