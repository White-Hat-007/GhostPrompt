-- GhostPrompt Database Initialization
-- Enables required PostgreSQL extensions

-- Enable pgvector for semantic embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Enable btree_gist for range queries
CREATE EXTENSION IF NOT EXISTS btree_gist;
