"""Entry point — starts the Telegram bot."""
from __future__ import annotations

import asyncio
import logging
import os
import sys

import config
from bot.handlers import build_application

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("bot.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# Suppress noisy httpx/httpcore logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)


def validate_config() -> None:
    """Fail fast if required environment variables are missing."""
    errors: list[str] = []
    if not config.TELEGRAM_BOT_TOKEN:
        errors.append("TELEGRAM_BOT_TOKEN is not set.")
    if config.AI_PROVIDER == "groq" and not config.GROQ_API_KEY:
        logger.warning("AI_PROVIDER=groq but GROQ_API_KEY not set — AI reports will fall back to structured mode.")
    if errors:
        for e in errors:
            logger.error(e)
        sys.exit(1)


def ensure_directories() -> None:
    os.makedirs("storage", exist_ok=True)
    os.makedirs(config.REPORT_DIR, exist_ok=True)


def main() -> None:
    validate_config()
    ensure_directories()

    logger.info("Starting Security Assessment Bot...")
    if config.AI_PROVIDER == "groq":
        ai_model = config.GROQ_MODEL
    elif config.AI_PROVIDER == "ollama":
        ai_model = config.OLLAMA_MODEL
    else:
        ai_model = "none"
    logger.info("AI provider: %s | Model: %s", config.AI_PROVIDER, ai_model)
    logger.info("Max scans/user/hour: %d", config.MAX_SCANS_PER_USER_PER_HOUR)

    if config.AUTHORIZED_USER_IDS:
        logger.info("Access restricted to %d authorized user(s).", len(config.AUTHORIZED_USER_IDS))
    else:
        logger.warning("No AUTHORIZED_USER_IDS set — all Telegram users can access this bot.")

    app = build_application(config.TELEGRAM_BOT_TOKEN)

    logger.info("Bot is running. Press Ctrl+C to stop.")
    app.run_polling(
        allowed_updates=["message", "callback_query"],
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()
