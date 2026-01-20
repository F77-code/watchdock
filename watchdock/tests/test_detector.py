from core.detector import CRASH_EXIT, LOG_ERROR, OOM, UNHEALTHY, classify_action, match_log


def test_log_markers() -> None:
    samples = [
        "FATAL: remaining connection slots are reserved",
        "Traceback (most recent call last):",
        "java.lang.NullPointerException",
        "Segmentation fault",
        '127.0.0.1 - "GET /login HTTP/1.1" 500 12',
        "dial tcp 10.0.0.3:5432: connection refused",
        "ERROR: deadlock detected",
        "runtime: out of memory",
    ]
    for line in samples:
        assert match_log(line), line
    assert match_log("INFO request finished") is False


def test_event_classification() -> None:
    assert classify_action("oom") == OOM
    assert classify_action("die", exit_code=1) == CRASH_EXIT
    assert classify_action("die", exit_code=137) == CRASH_EXIT
    assert classify_action("die", exit_code=0) is None
    assert classify_action("health_status: unhealthy") == UNHEALTHY
    assert classify_action("health_status: healthy") is None
    assert classify_action("start") is None
    assert LOG_ERROR == "LOG_ERROR"
