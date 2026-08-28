"""AIVPN — heuristic protocol picker for Amnezia Web Panel.

Picks the best installed VPN protocol on a server by strategy
(stealth / balanced / speed), optionally probing TCP reachability of ports.
This is panel-side selection (no remote AI daemon): invites, guest create,
and manual "pick now" use the same scorer.
"""

from __future__ import annotations

import logging
import socket
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

CLIENT_VPN_BASES = frozenset({
    'awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard',
    'xray', 'telemt', 'hysteria', 'naiveproxy', 'mieru',
})

# Higher = preferred for that strategy (0..100 base).
STRATEGY_WEIGHTS = {
    'stealth': {
        'xray': 100,
        'mieru': 96,
        'hysteria': 92,
        'naiveproxy': 88,
        'telemt': 70,
        'awg3': 64,
        'awg2': 58,
        'awg': 52,
        'awg_legacy': 48,
        'wireguard': 40,
    },
    'speed': {
        'awg3': 100,
        'awg2': 96,
        'awg': 92,
        'wireguard': 88,
        'hysteria': 86,
        'mieru': 78,
        'xray': 70,
        'naiveproxy': 62,
        'awg_legacy': 58,
        'telemt': 45,
    },
    'balanced': {
        'hysteria': 94,
        'mieru': 92,
        'xray': 90,
        'awg3': 88,
        'awg2': 84,
        'awg': 82,
        'naiveproxy': 78,
        'wireguard': 70,
        'telemt': 65,
        'awg_legacy': 60,
    },
}

STRATEGIES = frozenset(STRATEGY_WEIGHTS.keys())


def protocol_base(protocol: str) -> str:
    return str(protocol or '').split('__', 1)[0]


def get_aivpn_settings(server: dict) -> dict:
    info = server.get('server_info') or {}
    raw = info.get('aivpn') if isinstance(info, dict) else None
    if not isinstance(raw, dict):
        raw = {}
    strategy = str(raw.get('strategy') or 'balanced').lower()
    if strategy not in STRATEGIES:
        strategy = 'balanced'
    return {
        'enabled': bool(raw.get('enabled')),
        'strategy': strategy,
        'probe': bool(raw.get('probe', True)),
    }


def set_aivpn_settings(server: dict, *, enabled: Optional[bool] = None,
                       strategy: Optional[str] = None,
                       probe: Optional[bool] = None) -> dict:
    info = dict(server.get('server_info') or {})
    cur = get_aivpn_settings(server)
    if enabled is not None:
        cur['enabled'] = bool(enabled)
    if strategy is not None:
        s = str(strategy).lower()
        cur['strategy'] = s if s in STRATEGIES else 'balanced'
    if probe is not None:
        cur['probe'] = bool(probe)
    info['aivpn'] = cur
    server['server_info'] = info
    return cur


def _tcp_rtt_ms(host: str, port: int, timeout: float = 1.2) -> Optional[float]:
    if not host or not port:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.perf_counter() - t0) * 1000, 1)
    except OSError:
        return None


def _candidate_protocols(server: dict) -> list[str]:
    protocols = server.get('protocols') or {}
    out = []
    for key, info in protocols.items():
        if not isinstance(info, dict):
            continue
        if not info.get('installed'):
            continue
        if protocol_base(key) not in CLIENT_VPN_BASES:
            continue
        out.append(key)
    return out


def score_protocols(
    server: dict,
    *,
    strategy: str = 'balanced',
    probe: bool = False,
    live_status: Optional[dict] = None,
) -> list[dict[str, Any]]:
    """Return ranked protocol candidates with scores and reasons."""
    strategy = strategy if strategy in STRATEGIES else 'balanced'
    weights = STRATEGY_WEIGHTS[strategy]
    host = (server.get('host') or '').strip()
    protocols = server.get('protocols') or {}
    live_status = live_status or {}
    ranked = []

    for key in _candidate_protocols(server):
        base = protocol_base(key)
        info = protocols.get(key) or {}
        live = live_status.get(key) or {}
        reasons = []
        score = float(weights.get(base, 50))
        reasons.append(f'base:{strategy}={int(score)}')

        running = bool(live.get('container_running') or live.get('running'))
        exists = bool(
            live.get('container_exists')
            or live.get('installed')
            or info.get('installed')
        )
        if running:
            score += 18
            reasons.append('+running')
        elif exists:
            score -= 8
            reasons.append('-not_running')
        else:
            score -= 40
            reasons.append('-missing')

        port = live.get('port') or info.get('port')
        rtt = None
        if probe and host and port and base != 'telemt':
            # Telemt often shares 443 with other services; skip noisy probes.
            rtt = _tcp_rtt_ms(host, int(port))
            if rtt is None:
                score -= 25
                reasons.append('-port_unreachable')
            elif rtt < 40:
                score += 12
                reasons.append(f'+rtt:{rtt}ms')
            elif rtt < 120:
                score += 6
                reasons.append(f'+rtt:{rtt}ms')
            elif rtt < 250:
                reasons.append(f'rtt:{rtt}ms')
            else:
                score -= 8
                reasons.append(f'-slow:{rtt}ms')

        ranked.append({
            'protocol': key,
            'base': base,
            'score': round(score, 1),
            'port': port,
            'running': running,
            'rtt_ms': rtt,
            'reasons': reasons,
        })

    ranked.sort(key=lambda x: (-x['score'], x['protocol']))
    return ranked


def pick_protocol(
    server: dict,
    *,
    strategy: Optional[str] = None,
    probe: Optional[bool] = None,
    live_status: Optional[dict] = None,
) -> Optional[dict[str, Any]]:
    cfg = get_aivpn_settings(server)
    strat = strategy or cfg['strategy']
    do_probe = cfg['probe'] if probe is None else bool(probe)
    ranked = score_protocols(
        server,
        strategy=strat,
        probe=do_probe,
        live_status=live_status,
    )
    if not ranked:
        return None
    best = ranked[0]
    return {
        'protocol': best['protocol'],
        'base': best['base'],
        'score': best['score'],
        'strategy': strat if strat in STRATEGIES else 'balanced',
        'port': best.get('port'),
        'rtt_ms': best.get('rtt_ms'),
        'reasons': best.get('reasons') or [],
        'alternatives': ranked[1:5],
        'all': ranked,
    }


def resolve_provision_protocol(server: dict, requested: Optional[str] = None) -> str:
    """If requested is 'aivpn' (or empty while AIVPN enabled), pick automatically."""
    req = (requested or '').strip()
    cfg = get_aivpn_settings(server)
    if req and protocol_base(req) != 'aivpn':
        return req
    if req == 'aivpn' or (not req and cfg.get('enabled')):
        picked = pick_protocol(server, probe=False)
        if picked and picked.get('protocol'):
            return picked['protocol']
    return req or 'awg'
