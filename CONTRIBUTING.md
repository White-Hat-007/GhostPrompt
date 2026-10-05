# Contributing to GhostPrompt

Thank you for your interest in contributing to GhostPrompt!

## Development Setup

1. Fork and clone the repository
2. Install dependencies:
   ```bash
   # Backend
   cd backend && pip install -r requirements.txt

   # Frontend
   cd frontend && npm install
   ```
3. Start infrastructure:
   ```bash
   docker-compose up -d postgres redis
   ```
4. Run the development servers:
   ```bash
   # Backend
   uvicorn app.main:app --reload

   # Frontend
   npm run dev
   ```

## Code Style

- **Python**: Follow PEP 8, use `ruff` for linting
- **TypeScript**: Follow ESLint config, use Prettier for formatting
- **Commits**: Follow Conventional Commits format

## Pull Request Process

1. Create a feature branch from `develop`
2. Write tests for new functionality
3. Ensure all tests pass
4. Update documentation
5. Submit PR with clear description

## Security

If you discover a security vulnerability, please email security@ghostprompt.ai
instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed
under the project's Business Source License.
