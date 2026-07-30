# This file is a part of OwnCA,
# Certificate Authority GUI based on Django and OpenSSL
#
# Copyright (C) 2026 Ilya Maltsev
# email: i.y.maltsev@yandex.ru
#
# OwnCA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OwnCA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OwnCA.  If not, see <http://www.gnu.org/licenses/>.

"""
OwnCA — CryptoPro CSP backend integration.

Optional, certified-GOST backend that can stand in for openssl+gost-engine when
signing/keying GOST R 34.10-2012 material. This module owns everything that does
NOT touch the CA issuance path itself (that is `own_ca.py` + the `ownca_capi`
C-shim):

- availability / enablement gating (build marker + runtime env flag),
- provider status probe (`csptest`),
- license management (view / set, with a 90-day demo fallback when unset),
- DRBG "gamma" (external entropy) accounting: counting remaining draws,
  uploading / appending / (re)generating the CPSD pools.

Gating layers (see config.settings):
  available()  -> the marker file OWNCA_CRYPTOPRO_MARKER exists, i.e. the image
                  was built WITH the CryptoPro distribution staged in.
  enabled()    -> available() AND OWNCA_CRYPTOPRO_ENABLED is truthy at runtime.

Gamma format (CPSD reader, PoC-verified): the pool file is
a concatenation of 36-byte segments, each = 32 bytes of entropy + a 4-byte
little-endian CRC32 of those 32 bytes. CryptoPro consumes exactly one segment
(36 bytes) per `CryptGenKey`, from the tail. So:
    remaining draws (per pool file) = filesize // 36

Everything here is best-effort and defensive: when CryptoPro is not installed,
probes return structured "unavailable" results instead of raising, so the web UI
can render a disabled state without 500s.
"""
from __future__ import annotations

import logging
import os
import subprocess
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from django.conf import settings

logger = logging.getLogger('dashboard')


class CryptoProError(Exception):
    """Raised on an explicit CryptoPro management failure the caller must see
    (e.g. a bad license serial, a failed gamma write). Probes do NOT raise."""


# Gamma segment geometry (see module docstring).
GAMMA_DATA_LEN = 32
GAMMA_CRC_LEN = 4
GAMMA_SEGMENT_LEN = GAMMA_DATA_LEN + GAMMA_CRC_LEN  # 36
# CryptGenKey consumes one segment per key generation.
GAMMA_BYTES_PER_KEY = GAMMA_SEGMENT_LEN
# The CPSD pools the reader consumes, relative to the gamma dir.
GAMMA_POOL_FILES = ('db1/kis_1', 'db2/kis_1')


# ---------------------------------------------------------------------------
# gating
# ---------------------------------------------------------------------------

def _marker_path() -> Path:
    return Path(getattr(settings, 'OWNCA_CRYPTOPRO_MARKER', '/opt/app/.cryptopro_available'))


def available() -> bool:
    """True if the running image was built WITH CryptoPro (the Dockerfile wrote
    the build marker). Independent of the runtime enable flag."""
    try:
        return _marker_path().is_file()
    except OSError:
        return False


def runtime_flag() -> bool:
    """The raw runtime enable flag (OWNCA_CRYPTOPRO_ENABLED), ignoring build
    availability. Used by the UI to explain 'flag on but not installed'."""
    return bool(getattr(settings, 'OWNCA_CRYPTOPRO_ENABLED', False))


def enabled() -> bool:
    """True only when CryptoPro is BOTH installed in the image AND switched on
    at runtime. This is the gate `own_ca.py` consults to route GOST ops."""
    return available() and runtime_flag()


# ---------------------------------------------------------------------------
# CryptoPro CLI invocation
# ---------------------------------------------------------------------------

def _bin(name: str) -> str:
    """Absolute path to a CryptoPro CLI tool under the install root."""
    root = getattr(settings, 'OWNCA_CRYPTOPRO_ROOT', '/opt/cprocsp')
    return str(Path(root) / 'bin' / 'amd64' / name)


def _sbin(name: str) -> str:
    root = getattr(settings, 'OWNCA_CRYPTOPRO_ROOT', '/opt/cprocsp')
    return str(Path(root) / 'sbin' / 'amd64' / name)


def _run(cmd: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a CryptoPro CLI command, capturing output. Never raises for a
    non-zero exit — callers inspect returncode. Raises CryptoProError only when
    the binary is missing/timeouts, so probes can catch-and-degrade."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=timeout,
        )
    except FileNotFoundError as e:
        raise CryptoProError(f'CryptoPro binary not found: {cmd[0]}') from e
    except subprocess.TimeoutExpired as e:
        raise CryptoProError(f'CryptoPro command timed out: {" ".join(cmd)}') from e


# ---------------------------------------------------------------------------
# provider status
# ---------------------------------------------------------------------------

@dataclass
class ProviderInfo:
    available: bool
    enabled: bool
    runtime_flag: bool
    version: str = ''
    providers: list[str] = field(default_factory=list)
    error: str = ''


def status() -> ProviderInfo:
    """Best-effort provider probe. Never raises."""
    info = ProviderInfo(
        available=available(), enabled=enabled(), runtime_flag=runtime_flag(),
    )
    if not info.available:
        return info
    try:
        proc = _run([_bin('csptest'), '-enum', '-info'], timeout=20)
        out = (proc.stdout or '') + (proc.stderr or '')
        for line in out.splitlines():
            s = line.strip()
            if 'Type:' in s and ('GOST' in s or 'KC' in s or 'v5' in s.lower()):
                info.providers.append(s)
            if s.lower().startswith('ver') and not info.version:
                info.version = s
        if not info.version:
            # Fall back to the package version line if present.
            for line in out.splitlines():
                if 'Release Ver' in line or 'Build:' in line:
                    info.version = line.strip()
                    break
    except CryptoProError as e:
        info.error = str(e)
        logger.warning('CryptoPro status probe failed: %s', e)
    return info


# ---------------------------------------------------------------------------
# license
# ---------------------------------------------------------------------------

@dataclass
class LicenseInfo:
    available: bool
    configured_serial: str = ''   # serial we told CryptoPro to use (masked)
    source: str = ''              # 'ui' | 'env' | 'demo'
    raw: str = ''                 # `cpconfig -license -view` text
    expires: str = ''             # parsed expiry line, if any
    is_demo: bool = False
    error: str = ''


def mask_serial(serial: str) -> str:
    """Licence serial with its middle blanked out. Public because the
    configuration page shows the value of OWNCA_CRYPTOPRO_LICENSE and a serial
    is not something to render verbatim on a shared screen."""
    serial = (serial or '').strip()
    if len(serial) <= 5:
        return serial
    return serial[:5] + '-****-****-****-' + serial[-5:]


def effective_license_serial() -> tuple[str, str]:
    """Return (serial, source). A serial persisted via the web UI wins over the
    OWNCA_CRYPTOPRO_LICENSE env value. Empty serial => demo license."""
    # Imported lazily to avoid a hard model import at module load (migrations).
    try:
        from .models import CryptoProSettings
        ui_serial = (CryptoProSettings.get_solo().license_serial or '').strip()
    except Exception:  # DB not ready / table missing during migrate
        ui_serial = ''
    if ui_serial:
        return ui_serial, 'ui'
    env_serial = (getattr(settings, 'OWNCA_CRYPTOPRO_LICENSE', '') or '').strip()
    if env_serial:
        return env_serial, 'env'
    return '', 'demo'


def license_info() -> LicenseInfo:
    """Best-effort license probe. Never raises."""
    serial, source = effective_license_serial()
    info = LicenseInfo(
        available=available(), source=source,
        configured_serial=mask_serial(serial), is_demo=(source == 'demo'),
    )
    if not info.available:
        return info
    try:
        proc = _run([_sbin('cpconfig'), '-license', '-view'], timeout=20)
        info.raw = ((proc.stdout or '') + (proc.stderr or '')).strip()
        # `cpconfig -license -view` prints a header ("License validity:") before
        # the figures, and the header matches 'valid' too — taking the first
        # match landed that header in the UI instead of an expiry. Look for a
        # line that actually carries a value, and never accept a bare heading.
        def _informative(line: str) -> bool:
            return bool(line.strip()) and not line.strip().endswith(':')

        for keys in (('expir', 'срок', 'осталось'), ('valid', 'demo', 'trial')):
            for line in info.raw.splitlines():
                low = line.lower()
                if any(k in low for k in keys) and _informative(line):
                    info.expires = line.strip()
                    break
            if info.expires:
                break
        # The demo flag is read from the whole output, not from whichever line
        # happened to match first.
        if any(k in info.raw.lower() for k in ('demo', 'trial')):
            info.is_demo = True
    except CryptoProError as e:
        info.error = str(e)
        logger.warning('CryptoPro license probe failed: %s', e)
    return info


def apply_license(serial: str) -> None:
    """Push a license serial into CryptoPro via cpconfig. Raises CryptoProError
    on failure. An empty serial is a no-op (CryptoPro keeps its demo license)."""
    serial = (serial or '').strip()
    if not serial:
        return
    if not available():
        raise CryptoProError('CryptoPro is not installed in this image')
    proc = _run([_sbin('cpconfig'), '-license', '-set', serial], timeout=30)
    if proc.returncode != 0:
        msg = ((proc.stderr or '') + (proc.stdout or '')).strip() or 'unknown error'
        raise CryptoProError(f'license activation failed: {msg}')


def ensure_license() -> None:
    """Apply the effective license serial (UI > env) if any. Called at startup
    and after a UI change. Demo license needs no action. Never raises into the
    caller path — logs instead."""
    serial, source = effective_license_serial()
    if not serial:
        return
    try:
        apply_license(serial)
        logger.info('CryptoPro license applied from %s', source)
    except CryptoProError as e:
        logger.warning('CryptoPro license (%s) not applied: %s', source, e)


# ---------------------------------------------------------------------------
# gamma (DRBG entropy) accounting
# ---------------------------------------------------------------------------

def gamma_dir() -> Path:
    return Path(getattr(settings, 'OWNCA_CRYPTOPRO_GAMMA_DIR', '/var/opt/cprocsp/dsrf'))


@dataclass
class GammaFileStat:
    path: str
    # Path relative to the gamma dir ("db1/kis_1"). The UI labels rows with it:
    # the directory is already stated once above, and repeating it in every row
    # makes for a label too long to sit in its column.
    rel: str
    exists: bool
    bytes: int = 0
    segments: int = 0        # bytes // 36
    trailing_junk: int = 0   # bytes % 36 (should be 0 for a clean pool)


@dataclass
class GammaStatus:
    dir: str
    files: list[GammaFileStat] = field(default_factory=list)
    # The reader draws from the pools in step; the usable count is the MIN of
    # the per-pool segment counts (a key needs a segment from the active pool).
    draws_remaining: int = 0
    bytes_per_draw: int = GAMMA_BYTES_PER_KEY
    ok: bool = False


def gamma_status() -> GammaStatus:
    """Count remaining gamma draws across the CPSD pools. Never raises."""
    d = gamma_dir()
    st = GammaStatus(dir=str(d))
    seg_counts: list[int] = []
    for rel in GAMMA_POOL_FILES:
        p = d / rel
        fs = GammaFileStat(path=str(p), rel=rel, exists=False)
        try:
            if p.is_file():
                size = p.stat().st_size
                fs.exists = True
                fs.bytes = size
                fs.segments = size // GAMMA_SEGMENT_LEN
                fs.trailing_junk = size % GAMMA_SEGMENT_LEN
                seg_counts.append(fs.segments)
        except OSError as e:
            logger.warning('gamma stat failed for %s: %s', p, e)
        st.files.append(fs)
    st.draws_remaining = min(seg_counts) if seg_counts else 0
    st.ok = st.draws_remaining > 0
    return st


# ---------------------------------------------------------------------------
# gamma writing / formatting
# ---------------------------------------------------------------------------

def _segment(data32: bytes) -> bytes:
    """Wrap 32 bytes of entropy into a 36-byte CPSD segment (data + CRC32-LE)."""
    if len(data32) != GAMMA_DATA_LEN:
        raise CryptoProError(f'segment data must be {GAMMA_DATA_LEN} bytes')
    crc = zlib.crc32(data32) & 0xFFFFFFFF
    return data32 + crc.to_bytes(GAMMA_CRC_LEN, 'little')


def format_raw_gamma(raw: bytes) -> bytes:
    """Turn arbitrary raw entropy into a formatted CPSD pool: chop into 32-byte
    chunks and append a CRC32-LE to each. Trailing bytes shorter than 32 are
    dropped (a partial segment is unusable)."""
    out = bytearray()
    n = len(raw) // GAMMA_DATA_LEN
    for i in range(n):
        chunk = raw[i * GAMMA_DATA_LEN:(i + 1) * GAMMA_DATA_LEN]
        out += _segment(chunk)
    return bytes(out)


def generate_gamma(segments: int) -> bytes:
    """Generate a formatted pool of N segments from os.urandom.

    STAND / DEV ONLY — os.urandom is not a certified entropy source. Certified
    operation must feed a hardware FDSCH (or real CPSD gamma), not this."""
    if segments <= 0:
        raise CryptoProError('segment count must be positive')
    out = bytearray()
    for _ in range(segments):
        out += _segment(os.urandom(GAMMA_DATA_LEN))
    return bytes(out)


def validate_pool(data: bytes) -> int:
    """Validate a pre-formatted pool: length is a whole number of segments and
    every segment's CRC matches. Returns the segment count. Raises on bad data."""
    if not data:
        raise CryptoProError('empty gamma pool')
    if len(data) % GAMMA_SEGMENT_LEN != 0:
        raise CryptoProError(
            f'pool length {len(data)} is not a multiple of {GAMMA_SEGMENT_LEN}'
        )
    n = len(data) // GAMMA_SEGMENT_LEN
    for i in range(n):
        seg = data[i * GAMMA_SEGMENT_LEN:(i + 1) * GAMMA_SEGMENT_LEN]
        crc = zlib.crc32(seg[:GAMMA_DATA_LEN]) & 0xFFFFFFFF
        if seg[GAMMA_DATA_LEN:] != crc.to_bytes(GAMMA_CRC_LEN, 'little'):
            raise CryptoProError(f'CRC mismatch in segment {i + 1}/{n}')
    return n


def write_gamma(pool: bytes, *, mode: str = 'append') -> int:
    """Write a formatted pool to every CPSD pool file.

    mode='append' extends existing pools; mode='replace' overwrites them. Returns
    the number of segments written per file. Validates the pool first."""
    if mode not in ('append', 'replace'):
        raise CryptoProError(f'invalid mode {mode!r}')
    segs = validate_pool(pool)
    d = gamma_dir()
    for rel in GAMMA_POOL_FILES:
        p = d / rel
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            flag = 'ab' if mode == 'append' else 'wb'
            with open(p, flag) as f:
                f.write(pool)
        except OSError as e:
            raise CryptoProError(f'cannot write gamma pool {p}: {e}') from e
    logger.info('gamma %s: %d segments -> %s', mode, segs, ', '.join(GAMMA_POOL_FILES))
    return segs


def ingest_upload(data: bytes, *, raw: bool, mode: str = 'append') -> int:
    """Handle a web-UI gamma upload. If raw=True the bytes are unformatted
    entropy (we segment+CRC them); otherwise they must already be a valid
    formatted pool. Returns segments written per pool file."""
    pool = format_raw_gamma(data) if raw else data
    if not pool:
        raise CryptoProError('no usable gamma in upload (need at least 32 bytes)')
    return write_gamma(pool, mode=mode)
