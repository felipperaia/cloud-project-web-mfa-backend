import time
from typing import Dict, List, Tuple

# Memória: {key: [timestamps]}
_ATTEMPTS: Dict[str, List[float]] = {}

def is_allowed(key: str, max_attempts: int, window_sec: int) -> bool:
    now = time.time()
    window_start = now - window_sec
    timestamps = _ATTEMPTS.get(key, [])
    timestamps = [t for t in timestamps if t >= window_start]
    if len(timestamps) >= max_attempts:
        _ATTEMPTS[key] = timestamps
        return False
    timestamps.append(now)
    _ATTEMPTS[key] = timestamps
    return True
