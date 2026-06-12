"""Normalize reverse-engineered API payloads into stable renderer-friendly shapes."""

from __future__ import annotations

from typing import Any


def _coerce_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def normalize_user_info(data: dict[str, Any]) -> dict[str, Any]:
    basic = data.get("basic_info", data)
    interactions = data.get("interactions", [])

    stats = {}
    for item in interactions:
        stats[item.get("type", "")] = item.get("count", "0")

    return {
        "nickname": basic.get("nickname", basic.get("nick_name", "Unknown")),
        "red_id": basic.get("red_id", ""),
        "desc": basic.get("desc", ""),
        "ip_location": basic.get("ip_location", ""),
        "user_id": basic.get("user_id", data.get("user_id", "")),
        "gender": basic.get("gender"),
        "stats": stats,
    }


def normalize_note_detail(data: dict[str, Any]) -> dict[str, Any] | None:
    items = data.get("items", [])
    if not items:
        return None

    note = items[0].get("note_card", {})
    user = note.get("user", {})
    interact = note.get("interact_info", {})
    tags = note.get("tag_list", [])

    return {
        "title": note.get("title", "Untitled"),
        "desc": note.get("desc", ""),
        "author": user.get("nickname", "Unknown"),
        "liked_count": interact.get("liked_count", "0"),
        "collected_count": interact.get("collected_count", "0"),
        "comment_count": interact.get("comment_count", "0"),
        "share_count": interact.get("share_count", "0"),
        "tags": [tag.get("name", "") for tag in tags if tag.get("name")],
        "image_count": len(note.get("image_list", [])),
    }


def normalize_note_hydrate(
    data: dict[str, Any],
    *,
    note_id: str,
    xsec_token: str = "",
    xsec_source: str = "",
) -> dict[str, Any] | None:
    items = data.get("items", [])
    if not items:
        return None

    entry = items[0] if isinstance(items[0], dict) else {}
    note = entry.get("note_card", {}) if isinstance(entry.get("note_card"), dict) else {}
    user = note.get("user", {}) if isinstance(note.get("user"), dict) else {}
    interact = note.get("interact_info", {}) if isinstance(note.get("interact_info"), dict) else {}
    tags = note.get("tag_list", []) if isinstance(note.get("tag_list"), list) else []
    image_list = note.get("image_list", []) if isinstance(note.get("image_list"), list) else []
    note_type = "video" if note.get("type") == "video" else "image"
    actual_token = xsec_token or entry.get("xsec_token", note.get("xsec_token", ""))
    actual_source = xsec_source or "pc_feed"

    return {
        "id": note_id,
        "url": _build_note_url(note_id, actual_token, actual_source),
        "title": note.get("title") or note.get("display_title") or "Untitled",
        "body": note.get("desc", ""),
        "author": {
            "id": user.get("user_id", ""),
            "name": user.get("nickname", user.get("nick_name", "Unknown")),
        },
        "note_type": note_type,
        "liked_count": _coerce_int(interact.get("liked_count")),
        "collected_count": _coerce_int(interact.get("collected_count")),
        "comment_count": _coerce_int(interact.get("comment_count")),
        "share_count": _coerce_int(interact.get("share_count")),
        "tags": [tag.get("name", "") for tag in tags if isinstance(tag, dict) and tag.get("name")],
        "image_count": len(image_list),
        "images": _extract_note_images(image_list),
    }


def normalize_note_summary(item: dict[str, Any]) -> dict[str, Any] | None:
    note_card = item.get("note_card", item)
    if not isinstance(note_card, dict):
        return None
    user = note_card.get("user", {})
    interact = note_card.get("interact_info", {})
    return {
        "title": str(note_card.get("title", note_card.get("display_title", "")))[:40],
        "author": user.get("nickname", ""),
        "liked": str(interact.get("liked_count", "")),
        "note_type": "video" if note_card.get("type") == "video" else "image",
        "note_id": item.get("id", note_card.get("note_id", "")),
        "xsec_token": item.get("xsec_token", note_card.get("xsec_token", "")),
    }


def normalize_search_results(data: dict[str, Any]) -> dict[str, Any]:
    items = [item for item in (normalize_note_summary(item) for item in data.get("items", [])) if item]
    return {
        "items": items,
        "has_more": bool(data.get("has_more", False)),
    }


def normalize_comments(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for comment in data.get("comments", []):
        user = comment.get("user_info", {})
        normalized.append({
            "nickname": user.get("nickname", "Unknown"),
            "content": comment.get("content", ""),
            "like_count": comment.get("like_count", "0"),
            "sub_comment_count": _coerce_int(comment.get("sub_comment_count", 0)),
        })
    return normalized


def _extract_note_images(image_list: list[Any]) -> list[str]:
    urls: list[str] = []
    for image in image_list:
        if not isinstance(image, dict):
            continue
        url = _first_non_empty(
            image.get("url_default"),
            image.get("url_pre"),
            image.get("url"),
        )
        if not url:
            info_list = image.get("info_list", [])
            if isinstance(info_list, list):
                for info in info_list:
                    if not isinstance(info, dict):
                        continue
                    url = _first_non_empty(info.get("url"))
                    if url:
                        break
        normalized = _normalize_media_url(url)
        if normalized:
            urls.append(normalized)
    return urls


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _normalize_media_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("//"):
        return f"https:{text}"
    if text.startswith("http://"):
        return "https://" + text[len("http://"):]
    return text


def _build_note_url(note_id: str, xsec_token: str, xsec_source: str) -> str:
    base = f"https://www.xiaohongshu.com/explore/{note_id}"
    if not xsec_token:
        return base
    source = xsec_source or "pc_feed"
    return f"{base}?xsec_token={xsec_token}&xsec_source={source}"


def normalize_feed(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for item in data.get("items", [])[:20]:
        note_card = item.get("note_card", {})
        user = note_card.get("user", {})
        interact = note_card.get("interact_info", {})
        normalized.append({
            "title": note_card.get("title", note_card.get("display_title", ""))[:40],
            "author": user.get("nickname", ""),
            "liked": str(interact.get("liked_count", "")),
            "note_id": item.get("id", ""),
            "xsec_token": item.get("xsec_token", note_card.get("xsec_token", "")),
        })
    return normalized


def normalize_user_posts(notes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for note in notes:
        interact = note.get("interact_info", {})
        normalized.append({
            "title": note.get("display_title", "")[:40],
            "liked": str(interact.get("liked_count", note.get("liked_count", ""))),
            "note_type": "video" if note.get("type") == "video" else "image",
            "note_id": note.get("note_id", ""),
        })
    return normalized


def normalize_topics(data: Any) -> list[dict[str, Any]]:
    topics = data if isinstance(data, list) else data.get("topic_info_dtos", [])
    return [
        {
            "name": topic.get("name", ""),
            "view_num": topic.get("view_num", 0),
            "topic_id": topic.get("id", ""),
        }
        for topic in topics
    ]


def normalize_users(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        users = data
    elif isinstance(data, dict):
        users = data.get("user_info_dtos") or data.get("users") or data.get("items") or []
    else:
        users = []

    normalized = []
    for user in users:
        base = user.get("user_base_dto", user)
        normalized.append({
            "nickname": base.get("user_nickname", base.get("nickname", base.get("nick_name", ""))),
            "red_id": base.get("red_id", ""),
            "fans": user.get("fans_total", base.get("fans", base.get("fansCount", 0))),
            "user_id": base.get("user_id", base.get("id", "")),
        })
    return normalized


def normalize_creator_notes(data: Any) -> list[dict[str, Any]]:
    notes = data if isinstance(data, list) else data.get("notes", data.get("note_list", []))
    normalized = []
    for note in notes:
        interact = note.get("interact_info", {})
        normalized.append({
            "title": note.get("title", note.get("display_title", ""))[:40],
            "liked": str(note.get("liked_count", interact.get("liked_count", ""))),
            "comment_count": str(note.get("comment_count", interact.get("comment_count", ""))),
            "status": note.get("status"),
            "note_id": note.get("note_id", note.get("id", "")),
        })
    return normalized


def normalize_notifications(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for message in data.get("message_list", []):
        user = message.get("user_info", {}) or {}
        item = message.get("item_info", {}) or {}
        normalized.append({
            "nickname": user.get("nickname", ""),
            "title": message.get("title", ""),
            "note_content": item.get("content", ""),
            "time": message.get("time", 0),
        })
    return normalized
