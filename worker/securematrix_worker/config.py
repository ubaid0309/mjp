"""Worker configuration, read from environment variables (and an optional .env file)."""
from __future__ import annotations

import os
import shutil
import socket
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

VERSION = "0.4.0"
ROOT = Path(__file__).resolve().parent.parent
BUNDLED_RULES_DIR = ROOT / "rules" / "securematrix"
KNOWLEDGE_DIR = Path(os.getenv("SM_KNOWLEDGE_DIR", ROOT.parent / "knowledge"))


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    supabase_url: str = field(default_factory=lambda: os.getenv("SUPABASE_URL", "").rstrip("/"))
    service_key: str = field(default_factory=lambda: os.getenv("SUPABASE_SERVICE_ROLE_KEY", ""))

    # Embeddings: "openai" (default when a key is present), "local" (fastembed, optional install) or "none".
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_base_url: str = field(default_factory=lambda: os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"))
    embedding_provider: str = field(default_factory=lambda: os.getenv("EMBEDDING_PROVIDER", "").lower())
    openai_embedding_model: str = field(default_factory=lambda: os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"))
    local_embedding_model: str = field(default_factory=lambda: os.getenv("LOCAL_EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5"))
    openai_chat_model: str = field(default_factory=lambda: os.getenv("OPENAI_CHAT_MODEL", "gpt-4o-mini"))

    semgrep_bin: str = field(default_factory=lambda: os.getenv("SEMGREP_BIN") or shutil.which("semgrep") or "semgrep")
    semgrep_registry_url: str = field(default_factory=lambda: os.getenv("SEMGREP_REGISTRY_URL", "https://semgrep.dev/c"))
    semgrep_jobs: int = field(default_factory=lambda: _int("SEMGREP_JOBS", 2))
    semgrep_rule_timeout: int = field(default_factory=lambda: _int("SEMGREP_RULE_TIMEOUT", 20))

    # Hard ceilings that a project's scan settings can never exceed.
    max_archive_mb: int = field(default_factory=lambda: _int("SM_MAX_ARCHIVE_MB", 50))
    max_uncompressed_mb: int = field(default_factory=lambda: _int("SM_MAX_UNCOMPRESSED_MB", 500))
    max_archive_entries: int = field(default_factory=lambda: _int("SM_MAX_ARCHIVE_ENTRIES", 50000))
    max_compression_ratio: int = field(default_factory=lambda: _int("SM_MAX_COMPRESSION_RATIO", 200))

    work_dir: Path = field(default_factory=lambda: Path(os.getenv("SM_WORK_DIR", "/tmp/securematrix")))
    poll_seconds: int = field(default_factory=lambda: _int("SM_POLL_SECONDS", 3))
    api_port: int = field(default_factory=lambda: _int("SM_API_PORT", 8787))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        o.strip() for o in os.getenv("SM_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()))
    worker_id: str = field(default_factory=lambda: os.getenv("SM_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}"))

    @property
    def resolved_embedding_provider(self) -> str:
        if self.embedding_provider in {"openai", "local", "none"}:
            return self.embedding_provider
        return "openai" if self.openai_api_key else "none"

    @property
    def llm_configured(self) -> bool:
        return bool(self.openai_api_key)

    def require_supabase(self) -> None:
        missing = [n for n, v in (("SUPABASE_URL", self.supabase_url),
                                  ("SUPABASE_SERVICE_ROLE_KEY", self.service_key)) if not v]
        if missing:
            raise SystemExit(f"Missing required environment variables: {', '.join(missing)}. See worker/.env.example")


settings = Settings()
