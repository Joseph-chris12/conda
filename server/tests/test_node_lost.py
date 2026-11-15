from server.rules import node_lost


def test_boundary_is_strictly_greater_than_threshold(cfg):
    assert node_lost.check("N3", 30, cfg) is None          # tepat 30 detik: belum
    assert node_lost.check("N3", 29.9, cfg) is None
    f = node_lost.check("N3", 31, cfg)
    assert f and f["rule"] == "node_lost" and f["severity"] == "high"


def test_finding_commands_all_other_nodes(cfg):
    f = node_lost.check("N3", 60, cfg)
    assert f["node"] == "N3" and f["key"] == "N3" and f["cmd_nodes"] == ["all"]
    assert "Aula" in f["detail"] and f["evidence"]["silent_s"] == 60


def test_threshold_from_config(cfg):
    cfg.thresholds["node_lost_s"] = 10
    assert node_lost.check("N1", 11, cfg)


def test_disabled_rule(cfg):
    cfg.thresholds["rules"]["node_lost"]["enabled"] = False
    assert node_lost.check("N1", 999, cfg) is None
