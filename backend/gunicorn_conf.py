import multiprocessing
import os

# Gunicorn configuration file

# The number of worker processes for handling requests
# A common formula is (2 x $num_cores) + 1
cores = multiprocessing.cpu_count()
workers_per_core = float(os.getenv("WORKERS_PER_CORE", "2"))
default_web_concurrency = workers_per_core * cores + 1
web_concurrency = int(os.getenv("WEB_CONCURRENCY", default_web_concurrency))

# The host and port to bind to
host = os.getenv("HOST", "0.0.0.0")
port = os.getenv("PORT", "8000")
bind = f"{host}:{port}"

# The worker class to use (Uvicorn for ASGI)
worker_class = "uvicorn.workers.UvicornWorker"

# Other configurations
workers = web_concurrency
timeout = int(os.getenv("TIMEOUT", "120"))
keepalive = int(os.getenv("KEEP_ALIVE", "5"))

# Logging
loglevel = os.getenv("LOG_LEVEL", "info")
accesslog = "-"
errorlog = "-"
