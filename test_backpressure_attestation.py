"""Tests for the attestation queue's delay signal."""

from gsa_gateway import AttestationService


def _service(queue_size: int) -> AttestationService:
    return AttestationService(key=b"k" * 32, workers=1, queue_size=queue_size)


def test_empty_queue_has_no_delay():
    assert _service(10)._backpressure() == 0.0


def test_delay_stays_zero_below_watermark():
    svc = _service(100)
    for i in range(80):
        svc._queue.put_nowait(i)
    assert svc._backpressure() == 0.0


def test_full_queue_hits_ceiling():
    svc = _service(10)
    for i in range(10):
        svc._queue.put_nowait(i)
    assert svc._backpressure() == 0.002


def test_delay_rises_smoothly_between_watermark_and_full():
    svc = _service(100)
    for i in range(95):
        svc._queue.put_nowait(i)
    assert 0.0 < svc._backpressure() < 0.002


def test_unbounded_queue_has_no_delay():
    svc = _service(0)
    for i in range(50):
        svc._queue.put_nowait(i)
    assert svc._backpressure() == 0.0
