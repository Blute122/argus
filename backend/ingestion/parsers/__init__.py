"""Pluggable parsers: raw source data -> normalized flat log dict."""

from backend.ingestion.parsers.registry import parse, register

__all__ = ["parse", "register"]
