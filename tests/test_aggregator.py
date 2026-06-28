from ioc_enrichment.aggregator import compute_verdict


def test_no_data_is_unknown():
    assert compute_verdict([{"source": "virustotal", "status": "skipped"}]) == "unknown"


def test_clean_when_all_sources_clean():
    results = [
        {"source": "virustotal", "status": "ok", "malicious": 0, "suspicious": 0},
        {"source": "abuseipdb", "status": "ok", "abuse_confidence_score": 0},
    ]
    assert compute_verdict(results) == "clean"


def test_malicious_from_virustotal():
    results = [{"source": "virustotal", "status": "ok", "malicious": 3, "suspicious": 0}]
    assert compute_verdict(results) == "malicious"


def test_malicious_from_high_abuseipdb_score():
    results = [{"source": "abuseipdb", "status": "ok", "abuse_confidence_score": 90}]
    assert compute_verdict(results) == "malicious"


def test_suspicious_from_mid_abuseipdb_score():
    results = [{"source": "abuseipdb", "status": "ok", "abuse_confidence_score": 40}]
    assert compute_verdict(results) == "suspicious"


def test_malicious_wins_over_suspicious():
    results = [
        {"source": "virustotal", "status": "ok", "malicious": 0, "suspicious": 2},
        {"source": "abuseipdb", "status": "ok", "abuse_confidence_score": 90},
    ]
    assert compute_verdict(results) == "malicious"


def test_errored_and_skipped_sources_are_ignored_not_unknown():
    results = [
        {"source": "virustotal", "status": "error", "reason": "rate limited"},
        {"source": "abuseipdb", "status": "ok", "abuse_confidence_score": 0},
    ]
    assert compute_verdict(results) == "clean"
