from framework import metrics


def test_counter_and_histogram_render():
    metrics.inc_counter("threateye_test_total", (("k", "v"),))
    metrics.inc_counter("threateye_test_total", (("k", "v"),))
    metrics.observe("threateye_test_seconds", (("k", "v"),), 0.3)
    out = metrics.render()
    assert 'threateye_test_total{k="v"} 2' in out
    assert "threateye_test_seconds_bucket" in out
    assert 'le="+Inf"' in out
    assert "threateye_test_seconds_count" in out


def test_record_request():
    metrics.record_request("GET", "/api/stats", 200, 0.05)
    out = metrics.render()
    assert "threateye_http_requests_total" in out
    assert "threateye_http_request_duration_seconds_bucket" in out
