# Penset - Automated Pentesting Platform

A Django-based web application for visualizing and managing automated pentesting results. The platform provides a clean interface for security teams to view reports, track vulnerabilities, and manage their organization's security posture.

## Features

- **User Management**: Custom user model with organization-based access control
- **Report Visualization**: View and manage pentesting reports with detailed vulnerability information
- **Organization Support**: Multi-tenant architecture with organization-based data isolation
- **Modern UI**: Vue.js frontend with Tailwind CSS for a responsive and intuitive interface
- **AWS Integration**: S3 for file storage and SES for email notifications
- **REST API**: Full REST API for integration with external pentesting tools

## Technology Stack

- **Backend**: Django 4.2, Django REST Framework
- **Frontend**: Vue.js 3, Tailwind CSS, Vite
- **Database**: PostgreSQL
- **Cloud**: AWS (S3, SES)
- **Task Queue**: Celery with Redis

## Quick Start

### Prerequisites

- Python 3.9+
- [uv](https://github.com/astral-sh/uv) (fast Python package installer)
- Node.js 16+
- PostgreSQL
- Redis

### Installation

1. **Install uv** (if not already installed)
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   # Or on Windows: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

2. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd penset
   ```

3. **Quick setup with Make**
   ```bash
   make setup
   ```

   Or manually:

4. **Set up Python environment with uv**
   ```bash
   uv sync --extra dev
   ```

5. **Set up environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

6. **Set up the database**
   ```bash
   uv run python manage.py migrate
   uv run python manage.py create_superuser
   ```

7. **Set up frontend**
   ```bash
   npm install
   npm run build
   ```

8. **Run the development server**
   ```bash
   # Using Make
   make run
   
   # Or manually
   uv run python manage.py runserver
   
   # Terminal 2: Frontend (optional for development)
   npm run dev
   ```

### Environment Variables

Create a `.env` file with the following variables:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME=penset
DB_USER=postgres
DB_PASSWORD=your-password
DB_HOST=localhost
DB_PORT=5432

# AWS Settings
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_STORAGE_BUCKET_NAME=your-s3-bucket-name
AWS_S3_REGION_NAME=us-east-1
AWS_SES_REGION_NAME=us-east-1

# Redis
REDIS_URL=redis://localhost:6379/0
```

## API Endpoints

### Authentication
- `POST /api/accounts/api/register/` - User registration
- `POST /api/accounts/api/login/` - User login
- `POST /api/accounts/api/logout/` - User logout
- `GET /api/accounts/api/profile/` - Get user profile

### Reports
- `GET /api/reports/` - List reports
- `POST /api/reports/` - Create report
- `GET /api/reports/{id}/` - Get report details
- `PUT /api/reports/{id}/` - Update report
- `DELETE /api/reports/{id}/` - Delete report
- `GET /api/reports/statistics/` - Get report statistics

### Vulnerabilities
- `GET /api/reports/vulnerabilities/` - List vulnerabilities
- `POST /api/reports/vulnerabilities/` - Create vulnerability
- `GET /api/reports/vulnerabilities/{id}/` - Get vulnerability details
- `PUT /api/reports/vulnerabilities/{id}/` - Update vulnerability
- `DELETE /api/reports/vulnerabilities/{id}/` - Delete vulnerability

### Organizations
- `GET /api/organizations/` - List organizations (admin only)
- `GET /api/organizations/{id}/` - Get organization details
- `PUT /api/organizations/{id}/` - Update organization
- `GET /api/organizations/my/` - Get current user's organization

## User Roles

- **Administrator**: Full access to all features
- **Security Analyst**: Can view and edit reports and vulnerabilities
- **Viewer**: Read-only access to reports and vulnerabilities

## Development

### Development Tools

The project includes several development tools configured:

- **uv**: Fast Python package management
- **Make**: Convenient commands for common tasks
- **Pre-commit**: Git hooks for code quality
- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **pytest**: Testing

### Frontend Development

For frontend development with hot reload:

```bash
npm run dev
```

This will start the Vite development server on port 3000 with hot module replacement.

### Setting up Pre-commit Hooks

```bash
# Install pre-commit
uv run pre-commit install

# Run on all files
uv run pre-commit run --all-files
```

### Database Migrations

```bash
# Create migrations
uv run python manage.py makemigrations

# Apply migrations
uv run python manage.py migrate

# Or using Make
make makemigrations
make migrate
```

### Running Tests

```bash
# Using uv
uv run pytest

# Or using Make
make test
```

### Code Quality

```bash
# Format code
make format

# Run linting
make lint

# Or manually
uv run black .
uv run isort .
uv run flake8 .
```

## Deployment

### Production Settings

1. Set `DEBUG=False` in your environment
2. Configure proper `ALLOWED_HOSTS`
3. Set up a production database
4. Configure AWS credentials
5. Set up static file serving
6. Configure email settings

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.