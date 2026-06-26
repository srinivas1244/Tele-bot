"""Telegram bot handlers — conversation flow, authorization, scan dispatch."""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

import config
from bot.messages import (
    CONFIRMATION_MESSAGE,
    HELP_MESSAGE,
    INVALID_TARGET_MESSAGE,
    RATE_LIMIT_MESSAGE,
    SCAN_ALREADY_RUNNING_MESSAGE,
    SCAN_FAILED_MESSAGE,
    SCAN_STARTED_MESSAGE,
    UNAUTHORIZED_MESSAGE,
    WELCOME_MESSAGE,
    format_scan_summary,
    format_status_message,
)
from bot.rate_limit import rate_limiter
from report.ai_report import generate_ai_report
from report.json_report import export_json
from report.pdf_report import export_pdf
from scanner.core import normalize_target, run_scan

logger = logging.getLogger(__name__)

# Conversation states
AWAITING_TARGET = 1
AWAITING_CONFIRMATION = 2

_CONFIRM_YES = "confirm_yes"
_CONFIRM_NO = "confirm_no"


def _is_authorized(user_id: int) -> bool:
    if not config.AUTHORIZED_USER_IDS:
        return True
    return user_id in config.AUTHORIZED_USER_IDS


async def _send_unauthorized(update: Update) -> None:
    await update.message.reply_text(UNAUTHORIZED_MESSAGE, parse_mode=ParseMode.MARKDOWN)


# ── /start command ────────────────────────────────────────────────────────────
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not _is_authorized(user_id):
        await _send_unauthorized(update)
        return ConversationHandler.END

    await update.message.reply_text(WELCOME_MESSAGE, parse_mode=ParseMode.MARKDOWN)
    return AWAITING_TARGET


# ── /help command ─────────────────────────────────────────────────────────────
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(HELP_MESSAGE, parse_mode=ParseMode.MARKDOWN)


# ── /status command ───────────────────────────────────────────────────────────
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not _is_authorized(user_id):
        await _send_unauthorized(update)
        return

    remaining = rate_limiter.remaining(user_id)
    msg = format_status_message(user_id, remaining, config.MAX_SCANS_PER_USER_PER_HOUR)
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


# ── /scan command ─────────────────────────────────────────────────────────────
async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not _is_authorized(user_id):
        await _send_unauthorized(update)
        return ConversationHandler.END

    args = context.args
    if args:
        target = " ".join(args).strip()
        return await _handle_target_input(update, context, target)

    await update.message.reply_text(
        "Please send me the URL, domain, or IP address you want to scan.",
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAITING_TARGET


# ── Free-text URL input ───────────────────────────────────────────────────────
async def receive_target(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not _is_authorized(user_id):
        await _send_unauthorized(update)
        return ConversationHandler.END

    target = update.message.text.strip()
    return await _handle_target_input(update, context, target)


async def _handle_target_input(update: Update, context: ContextTypes.DEFAULT_TYPE, target: str) -> int:
    user_id = update.effective_user.id

    # Rate limit check
    allowed, reset_in = rate_limiter.is_allowed(user_id)
    if not allowed:
        reset_minutes = (reset_in // 60) + 1
        await update.message.reply_text(
            RATE_LIMIT_MESSAGE.format(
                max_scans=config.MAX_SCANS_PER_USER_PER_HOUR,
                reset_minutes=reset_minutes,
            ),
            parse_mode=ParseMode.MARKDOWN,
        )
        return ConversationHandler.END

    # Active scan check
    if rate_limiter.is_active(user_id):
        await update.message.reply_text(SCAN_ALREADY_RUNNING_MESSAGE, parse_mode=ParseMode.MARKDOWN)
        return ConversationHandler.END

    # Validate target
    try:
        normalized, target_type = normalize_target(target)
    except ValueError:
        await update.message.reply_text(
            INVALID_TARGET_MESSAGE.format(target=target),
            parse_mode=ParseMode.MARKDOWN,
        )
        return AWAITING_TARGET

    # Store in context for the confirmation step
    context.user_data["pending_target"] = normalized
    context.user_data["target_type"] = target_type

    keyboard = [
        [
            InlineKeyboardButton("✅ I Confirm — Proceed with Scan", callback_data=_CONFIRM_YES),
            InlineKeyboardButton("❌ Cancel", callback_data=_CONFIRM_NO),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        CONFIRMATION_MESSAGE.format(target=normalized),
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAITING_CONFIRMATION


# ── Confirmation callback ─────────────────────────────────────────────────────
async def confirmation_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()

    user_id = update.effective_user.id
    choice = query.data

    if choice == _CONFIRM_NO:
        await query.edit_message_text("❌ Scan cancelled.", parse_mode=ParseMode.MARKDOWN)
        context.user_data.clear()
        return ConversationHandler.END

    if choice != _CONFIRM_YES:
        return AWAITING_CONFIRMATION

    target = context.user_data.get("pending_target")
    if not target:
        await query.edit_message_text("⚠️ Session expired. Please start again.", parse_mode=ParseMode.MARKDOWN)
        return ConversationHandler.END

    # Final rate limit check (concurrent safety)
    allowed, reset_in = rate_limiter.is_allowed(user_id)
    if not allowed:
        reset_minutes = (reset_in // 60) + 1
        await query.edit_message_text(
            RATE_LIMIT_MESSAGE.format(
                max_scans=config.MAX_SCANS_PER_USER_PER_HOUR,
                reset_minutes=reset_minutes,
            ),
            parse_mode=ParseMode.MARKDOWN,
        )
        return ConversationHandler.END

    if not rate_limiter.mark_active(user_id):
        await query.edit_message_text(SCAN_ALREADY_RUNNING_MESSAGE, parse_mode=ParseMode.MARKDOWN)
        return ConversationHandler.END

    rate_limiter.record(user_id)

    await query.edit_message_text(
        SCAN_STARTED_MESSAGE.format(
            target=target,
            scan_id=datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        ),
        parse_mode=ParseMode.MARKDOWN,
    )

    # Run scan in background
    asyncio.create_task(
        _execute_scan(update, context, target, user_id)
    )
    return ConversationHandler.END


async def _execute_scan(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    target: str,
    user_id: int,
) -> None:
    """Execute the full scan pipeline and send results."""
    chat_id = update.effective_chat.id

    try:
        # Show typing indicator
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)

        # Run scan
        result = await run_scan(target, user_id)

        if result.status.value == "failed":
            await context.bot.send_message(
                chat_id=chat_id,
                text=SCAN_FAILED_MESSAGE.format(target=target, error=result.error or "Unknown error"),
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        # Generate AI report
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
        ai_report_text = await generate_ai_report(result)
        result.ai_report = ai_report_text

        # Send Telegram summary
        summary = format_scan_summary(result)
        await context.bot.send_message(
            chat_id=chat_id,
            text=summary,
            parse_mode=ParseMode.MARKDOWN,
        )

        # Export and send JSON report
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.UPLOAD_DOCUMENT)
        json_path = export_json(result)
        if os.path.exists(json_path):
            with open(json_path, "rb") as fh:
                await context.bot.send_document(
                    chat_id=chat_id,
                    document=fh,
                    filename=os.path.basename(json_path),
                    caption="📄 JSON Report",
                )

        # Export and send PDF report
        await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.UPLOAD_DOCUMENT)
        pdf_path = export_pdf(result, ai_report_text)
        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as fh:
                await context.bot.send_document(
                    chat_id=chat_id,
                    document=fh,
                    filename=os.path.basename(pdf_path),
                    caption="📋 PDF Report",
                )

        # Send AI report as a text message if it fits, otherwise truncate
        if ai_report_text:
            # Telegram max message size is ~4096 chars
            ai_preview = ai_report_text[:3800]
            if len(ai_report_text) > 3800:
                ai_preview += "\n\n_(Report truncated — full report in PDF)_"
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🤖 *AI Security Analysis:*\n\n{ai_preview}",
                parse_mode=ParseMode.MARKDOWN,
            )

    except Exception as exc:
        logger.exception("Error in scan execution for %s: %s", target, exc)
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"❌ An unexpected error occurred during the scan: {exc}",
            )
        except Exception:
            pass
    finally:
        rate_limiter.mark_done(user_id)
        context.user_data.clear()


# ── Fallback / cancel ─────────────────────────────────────────────────────────
async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text("Scan request cancelled. Send /scan to start a new one.")
    return ConversationHandler.END


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "I don't recognise that command. Use /help for available commands or just send a URL to scan."
    )


def build_application(token: str) -> Application:
    """Build and configure the Telegram Application."""
    app = Application.builder().token(token).build()

    # Conversation handler
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start_command),
            CommandHandler("scan", scan_command),
            MessageHandler(filters.TEXT & ~filters.COMMAND, receive_target),
        ],
        states={
            AWAITING_TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_target),
            ],
            AWAITING_CONFIRMATION: [
                CallbackQueryHandler(confirmation_callback, pattern=f"^({_CONFIRM_YES}|{_CONFIRM_NO})$"),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_command)],
        allow_reentry=True,
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    return app
