"""Проверка времени по нескольким сетевым источникам и локальным часам."""

from __future__ import annotations

import json
import socket
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from statistics import median
from typing import Callable

from .settings import VaultSettings

USER_AGENT = "EncryptedVault/1.0 (time-verify)"


@dataclass
class TimeSample:
    source: str
    unix: float
    is_local: bool = False


@dataclass
class TrustedTime:
    unix: float
    utc: datetime
    samples: list[TimeSample]
    network_median: float
    local_unix: float
    local_skew_seconds: float


class TimeVerificationError(RuntimeError):
    pass


def _http_get(url: str, timeout: float = 8.0) -> tuple[bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.read(), headers


def _sample_worldtimeapi() -> TimeSample:
    data, _ = _http_get("https://worldtimeapi.org/api/timezone/Etc/UTC")
    payload = json.loads(data.decode("utf-8"))
    raw = payload.get("unixtime")
    if raw is None:
        raw = datetime.fromisoformat(payload["utc_datetime"].replace("Z", "+00:00")).timestamp()
    return TimeSample("worldtimeapi.org", float(raw))


def _sample_timeapi_io() -> TimeSample:
    data, _ = _http_get("https://timeapi.io/api/Time/current/zone?timeZone=UTC")
    payload = json.loads(data.decode("utf-8"))
    dt = datetime(
        payload["year"],
        payload["month"],
        payload["day"],
        payload["hour"],
        payload["minute"],
        payload["seconds"],
        tzinfo=timezone.utc,
    )
    return TimeSample("timeapi.io", dt.timestamp())


def _sample_http_date(url: str, name: str) -> TimeSample:
    _, headers = _http_get(url)
    date_hdr = headers.get("date")
    if not date_hdr:
        raise TimeVerificationError(f"нет заголовка Date: {name}")
    dt = parsedate_to_datetime(date_hdr)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return TimeSample(name, dt.astimezone(timezone.utc).timestamp())


def _sample_cloudflare_trace() -> TimeSample:
    data, _ = _http_get("https://www.cloudflare.com/cdn-cgi/trace")
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("ts="):
            ts = float(line.split("=", 1)[1])
            return TimeSample("cloudflare.com", ts)
    raise TimeVerificationError("cloudflare trace: нет ts=")


def _sample_ntp(host: str = "pool.ntp.org") -> TimeSample:
    packet = b"\x1b" + 47 * b"\0"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(6.0)
        sock.sendto(packet, (host, 123))
        data, _ = sock.recvfrom(256)
    if len(data) < 48:
        raise TimeVerificationError(f"ntp {host}: короткий ответ")
    transmit_ts = struct.unpack("!I", data[40:44])[0]
    fraction = struct.unpack("!I", data[44:48])[0]
    ntp = transmit_ts + fraction / 2**32
    unix = ntp - 2208988800
    return TimeSample(f"ntp:{host}", unix)


def _sample_local() -> TimeSample:
    return TimeSample("local_clock", datetime.now(timezone.utc).timestamp(), is_local=True)


def _collect_samples(cfg: VaultSettings) -> list[TimeSample]:
    fetchers: list[Callable[[], TimeSample]] = [
        _sample_worldtimeapi,
        _sample_timeapi_io,
        lambda: _sample_http_date("https://www.google.com/generate_204", "google.com"),
        lambda: _sample_http_date("https://www.microsoft.com/favicon.ico", "microsoft.com"),
        _sample_cloudflare_trace,
        lambda: _sample_ntp("pool.ntp.org"),
        lambda: _sample_ntp("time.google.com"),
        _sample_local,
    ]
    samples: list[TimeSample] = []
    errors: list[str] = []
    for fn in fetchers:
        try:
            samples.append(fn())
        except (OSError, urllib.error.URLError, TimeoutError, TimeVerificationError, json.JSONDecodeError, KeyError, ValueError) as e:
            errors.append(f"{fn.__name__ if hasattr(fn, '__name__') else 'source'}: {e}")
    if not any(s.is_local for s in samples):
        samples.append(_sample_local())
    return samples


def _cluster_network(samples: list[TimeSample], agreement_sec: float) -> list[TimeSample]:
    network = [s for s in samples if not s.is_local]
    if len(network) < 2:
        return network
    med = median(s.unix for s in network)
    cluster = [s for s in network if abs(s.unix - med) <= agreement_sec]
    return cluster if len(cluster) >= 2 else network


def get_trusted_time(cfg: VaultSettings) -> TrustedTime:
    """Согласованное UTC-время: кворум сетевых серверов + проверка локальных часов."""
    samples = _collect_samples(cfg)
    local_samples = [s for s in samples if s.is_local]
    local_unix = local_samples[0].unix if local_samples else datetime.now(timezone.utc).timestamp()

    network_cluster = _cluster_network(samples, cfg.time_lock_network_agreement_seconds)
    network_ok = len(network_cluster) >= cfg.time_lock_min_network_sources

    if not network_ok:
        if cfg.time_lock_require_network and not cfg.time_lock_allow_offline:
            network_names = [s.source for s in samples if not s.is_local]
            raise TimeVerificationError(
                "Не удалось получить согласованное время из интернета "
                f"(нужно ≥{cfg.time_lock_min_network_sources} источников, "
                f"получено {len(network_cluster)}). "
                "Проверьте подключение к сети или отключите time_lock_require_network."
            )
        trusted_unix = local_unix
        network_median = local_unix
    else:
        network_median = float(median(s.unix for s in network_cluster))
        trusted_unix = network_median

    local_skew = abs(local_unix - network_median) if network_ok else 0.0

    if network_ok and local_skew > cfg.time_lock_max_local_skew_seconds:
        raise TimeVerificationError(
            f"Локальные часы расходятся с интернет-временем на {local_skew:.0f} с "
            f"(допуск {cfg.time_lock_max_local_skew_seconds} с). "
            "Сбросьте подделку даты/времени в системе — иначе открытие заблокировано."
        )

    if network_ok and cfg.time_lock_require_local_match:
        if local_skew > cfg.time_lock_max_local_skew_seconds:
            raise TimeVerificationError("Локальные часы не прошли сверку с сетью.")

    return TrustedTime(
        unix=trusted_unix,
        utc=datetime.fromtimestamp(trusted_unix, tz=timezone.utc),
        samples=samples,
        network_median=network_median,
        local_unix=local_unix,
        local_skew_seconds=local_skew,
    )


def format_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
