"""User subscription expiration helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Union


def _parse_dt(value: Union[str, datetime, None]) -> Optional[datetime]:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _as_utc(dt: datetime) -> datetime:
    """Normalize naive/aware datetimes for safe comparison."""
    if dt.tzinfo is None:
        # Treat naive wall time as local, then convert to UTC.
        return dt.astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)


def user_is_expired(user: dict, *, now: Optional[datetime] = None) -> bool:
    """True when absolute expiration_date is in the past."""
    exp_date = _parse_dt(user.get('expiration_date'))
    if not exp_date:
        return False
    stamp = now if now is not None else datetime.now().astimezone()
    try:
        return _as_utc(stamp) > _as_utc(exp_date)
    except Exception:
        return False


def maybe_start_user_expiration(data: dict, user_id: str, *, now: Optional[datetime] = None) -> Optional[str]:
    """If user waits for first config use, start the countdown.

    Returns the new expiration_date ISO string when activated, else None.
    """
    if not user_id:
        return None
    user = next((u for u in data.get('users', []) if u.get('id') == user_id), None)
    if not user:
        return None
    if not user.get('expire_after_first_use'):
        return None
    if user.get('expiration_date'):
        return None
    days = int(user.get('expiration_days') or 0)
    if days <= 0:
        return None
    stamp = now if now is not None else datetime.now()
    expires = stamp + timedelta(days=days)
    # Store without tz so UI/local comparisons stay consistent with manual dates
    if expires.tzinfo is not None:
        expires = expires.replace(tzinfo=None)
    iso = expires.isoformat(timespec='seconds')
    user['expiration_date'] = iso
    return iso
