"""Pembuat data uji: bentuknya sama persis dengan baris gateway (docs/protokol.md §3)."""
import json

OFFICIAL_BSSID = "d8:07:b6:10:00:01"     # SATUAN-01 (WPA2 / WPA3_TRANSITION / WPA3)
OFFICIAL_BSSID_2 = "d8:07:b6:10:00:02"   # BSSID kedua SATUAN-01
LOGISTIK_BSSID = "f4:f2:6d:30:00:01"     # LOGISTIK-NET (hanya WPA2)
ATTACKER = "aa:bb:cc:dd:ee:01"


def ap(ssid="SATUAN-01", bssid=ATTACKER, ch=6, rssi=-50, sec="WPA2"):
    d = {"ssid": ssid, "bssid": bssid, "ch": ch, "rssi": rssi, "sec": sec}
    if ssid == "":
        d["hidden"] = True
    return d


def ap_msg(aps, node="N1", ts=1000.0, cycle=1):
    return {"v": 1, "t": "ap", "node": node, "cycle": cycle, "gw_ms": int(ts * 1000), "ts": ts, "aps": aps}


def deauth_item(bssid=OFFICIAL_BSSID, deauth=20, disassoc=0, rssi=-55, ch=6, bcast=True):
    return {"bssid": bssid, "ch": ch, "deauth": deauth, "disassoc": disassoc, "rssi": rssi, "bcast": bcast}


def deauth_msg(items, node="N1", ts=1000.0, cycle=1):
    return {"v": 1, "t": "deauth", "node": node, "cycle": cycle, "ts": ts, "items": items}


def ble_item(addr="c7:4a:91:3e:5b:21", rssi=-65, company="004c", mtype="12", svc=None, info=16):
    return {"addr": addr, "atype": "random", "rssi": rssi, "company": company, "mtype": mtype,
            "svc": svc, "info": info}


def ble_msg(items, node="N2", ts=1000.0, cycle=1):
    return {"v": 1, "t": "ble", "node": node, "cycle": cycle, "ts": ts, "items": items}


def hb_msg(node="N1", ts=1000.0, cycle=1, uptime=100):
    return {"v": 1, "t": "hb", "node": node, "cycle": cycle, "ts": ts, "uptime_s": uptime,
            "heap_kb": 180, "cycle_ms": 5800, "fw": 1, "led_red": False, "buzzer": False}


def alerts_of(events):
    return [e for e in events if e["t"] == "alert"]


def threat_alerts(events):
    """Alert selain node_lost. Tes yang melompati waktu >30 detik memakai ini, karena node yang
    tidak ikut melapor memang (dengan benar) dianggap hilang."""
    return [e for e in events if e["t"] == "alert" and e["rule"] != "node_lost"]


def line(msg):
    return json.dumps(msg)
