"""
t5_backend.py — Web API adapter for t5_wizard.py

Wraps the existing t5_wizard discover/action/guided_build logic
into clean functions that the Flask app.py can call.
Returns dicts suitable for JSON serialization.
"""

import json
import os
import t5_wizard as t5

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NODES_FILE = os.path.join(BASE_DIR, "t5_nodes.json")

TL1_UID = os.environ.get("TL1_UID", "CISCO15")
TL1_PID = os.environ.get("TL1_PID", "otbu+1")


class T5Error(Exception):
    pass


class T5Unreachable(T5Error):
    pass


def load_nodes():
    with open(NODES_FILE) as f:
        return json.load(f)


def get_node(node_id):
    for n in load_nodes():
        if n["id"] == node_id:
            return n
    return None


def _to_t5_node(node_cfg):
    return t5.Node(ip=node_cfg["host"], tl1_port=node_cfg.get("tl1_port", 3082),
                   name=node_cfg["id"])


# ── Discovery ──

def discover_cards(node_id):
    """Discover all 400G-XP-LC cards on a node. Returns list of card dicts."""
    node_cfg = get_node(node_id)
    if not node_cfg:
        raise T5Error("Unknown node: {}".format(node_id))
    node = _to_t5_node(node_cfg)
    try:
        cards = t5.discover(node, TL1_UID, TL1_PID)
    except Exception as e:
        raise T5Unreachable("Cannot reach {}: {}".format(node_id, e))
    return [_card_to_dict(c) for c in cards]


def _card_to_dict(card):
    return {
        "shelf": card.shelf,
        "slot": card.slot,
        "opmode": card.opmode,
        "trunkopmode": card.trunkopmode,
        "clientsets": card.clientsets,
        "client_trunk": card.client_trunk,
        "ports": [_port_to_dict(p, card) for p in card.ports],
    }


def _port_to_dict(port, card):
    d = {
        "port": port.port,
        "kind": port.kind,
        "optic": port.optic,
        "facility": port.facility,
        "provisioned": port.provisioned,
        "state": port.state,
    }
    if port.kind == "trunk":
        d["freq"] = port.freq
    if port.kind == "client":
        d["trunk_port"] = card.client_trunk.get(port.port)
    # compute legal actions
    actions = t5.available_actions(port)
    d["actions"] = [{"key": k, "label": l, "destructive": ds} for k, l, ds in actions]
    return d


# ── Port actions ──

def execute_action(node_id, shelf, slot, port_num, action_key, freq=None):
    """Execute a single action on a port. Returns (success, message)."""
    node_cfg = get_node(node_id)
    if not node_cfg:
        raise T5Error("Unknown node: {}".format(node_id))
    node = _to_t5_node(node_cfg)

    # discover to get the port object
    try:
        cards = t5.discover(node, TL1_UID, TL1_PID)
    except Exception as e:
        raise T5Unreachable(str(e))

    card = None
    for c in cards:
        if c.shelf == shelf and c.slot == slot:
            card = c
            break
    if not card:
        raise T5Error("Card SLOT-{}-{} not found".format(shelf, slot))

    port = None
    for p in card.ports:
        if p.port == port_num:
            port = p
            break
    if not port:
        raise T5Error("Port {} not found on SLOT-{}-{}".format(port_num, shelf, slot))

    # validate action is legal
    legal_keys = [a[0] for a in t5.available_actions(port)]
    if action_key not in legal_keys:
        raise T5Error("Action '{}' is not legal for port {} in current state".format(
            action_key, port_num))

    # execute
    try:
        sock, sess = t5._open(node, TL1_UID, TL1_PID)
    except Exception as e:
        raise T5Unreachable(str(e))

    try:
        handler = t5._apply_client if port.kind == "client" else t5._apply_trunk
        ok = handler(sess, port, action_key, freq)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return ok, "OK (verified)" if ok else "FAILED / not verified"


# ── Guided build ──

def guided_build_plan(node_id, shelf, slot, client_port, freq=None):
    """
    Compute the guided build plan for a client port.
    Returns the plan steps without executing them.
    """
    node_cfg = get_node(node_id)
    if not node_cfg:
        raise T5Error("Unknown node: {}".format(node_id))
    node = _to_t5_node(node_cfg)

    try:
        cards = t5.discover(node, TL1_UID, TL1_PID)
    except Exception as e:
        raise T5Unreachable(str(e))

    card = None
    for c in cards:
        if c.shelf == shelf and c.slot == slot:
            card = c
            break
    if not card:
        raise T5Error("Card not found")

    client = None
    for p in card.ports:
        if p.kind == "client" and p.port == client_port:
            client = p
            break
    if not client:
        raise T5Error("Client port {} not found".format(client_port))
    if not client.optic:
        raise T5Error("No optic present on client port {}".format(client_port))

    tport = card.client_trunk.get(client.port)
    trunk = next((p for p in card.ports if p.kind == "trunk" and p.port == tport), None)

    plan = []
    trunk_needs_freq = False

    if trunk and not t5._is_up(trunk.state):
        trunk_needs_freq = not trunk.freq and not freq
        use_freq = freq or trunk.freq
        if use_freq:
            plan.append({
                "key": "trunk_freq",
                "description": "Set trunk {} FREQ={}".format(trunk.port, use_freq),
                "trunk_port": trunk.port,
                "freq": use_freq,
            })
        plan.append({
            "key": "trunk_up",
            "description": "Bring trunk {} in service".format(trunk.port),
            "trunk_port": trunk.port,
        })
    elif trunk:
        pass  # trunk already up

    if not client.provisioned:
        plan.append({
            "key": "client_create",
            "description": "Create 100GIGE facility on client {}".format(client.port),
            "client_port": client.port,
        })

    if not t5._is_up(client.state):
        plan.append({
            "key": "client_up",
            "description": "Bring client {} in service".format(client.port),
            "client_port": client.port,
        })

    return {
        "client_port": client.port,
        "client_facility": client.facility,
        "trunk_port": tport,
        "trunk_facility": trunk.facility if trunk else None,
        "trunk_freq": trunk.freq if trunk else None,
        "trunk_needs_freq": trunk_needs_freq,
        "already_done": len(plan) == 0,
        "steps": plan,
    }


def guided_build_execute(node_id, shelf, slot, client_port, freq=None):
    """
    Execute the full guided build for a client port.
    Returns list of step results.
    """
    node_cfg = get_node(node_id)
    if not node_cfg:
        raise T5Error("Unknown node: {}".format(node_id))
    node = _to_t5_node(node_cfg)

    try:
        cards = t5.discover(node, TL1_UID, TL1_PID)
    except Exception as e:
        raise T5Unreachable(str(e))

    card = None
    for c in cards:
        if c.shelf == shelf and c.slot == slot:
            card = c
            break
    if not card:
        raise T5Error("Card not found")

    client = None
    for p in card.ports:
        if p.kind == "client" and p.port == client_port:
            client = p
            break
    if not client:
        raise T5Error("Client port {} not found".format(client_port))

    tport = card.client_trunk.get(client.port)
    trunk = next((p for p in card.ports if p.kind == "trunk" and p.port == tport), None)

    caid = client.facility
    taid = trunk.facility if trunk else None

    try:
        sock, sess = t5._open(node, TL1_UID, TL1_PID)
    except Exception as e:
        raise T5Unreachable(str(e))

    results = []
    try:
        # Trunk freq
        if trunk and not t5._is_up(trunk.state):
            use_freq = freq or trunk.freq
            if use_freq:
                ok, msg = t5._guided_run(
                    sess, "ED-OTU4C2::{}:{{c}}:::FREQ={}".format(taid, use_freq),
                    tolerate=("SROF",))
                results.append({"step": "trunk_freq", "description": "Set trunk {} FREQ={}".format(trunk.port, use_freq), "ok": ok, "message": msg})
                if not ok:
                    return results

            # Trunk up
            ok, msg = t5._guided_run(
                sess, "ED-OTU4C2::{}:{{c}}::::IS".format(taid),
                "RTRV-OTU4C2::{}:{{c}}".format(taid), "IS", tolerate=("SAIN",))
            results.append({"step": "trunk_up", "description": "Bring trunk {} IS".format(trunk.port), "ok": ok, "message": msg})
            if not ok:
                return results

        # Client create
        if not client.provisioned:
            ok, msg = t5._guided_run(
                sess, "ENT-100GIGE::{}:{{c}}:::NUMOFLANES=4".format(caid),
                "RTRV-100GIGE::{}:{{c}}".format(caid))
            results.append({"step": "client_create", "description": "Create 100GIGE on client {}".format(client.port), "ok": ok, "message": msg})
            if not ok:
                return results

        # Client up
        if not t5._is_up(client.state):
            ok, msg = t5._guided_run(
                sess, "ED-100GIGE::{}:{{c}}::::IS".format(caid),
                "RTRV-100GIGE::{}:{{c}}".format(caid), "IS", tolerate=("SAIN",))
            results.append({"step": "client_up", "description": "Bring client {} IS".format(client.port), "ok": ok, "message": msg})

    finally:
        try:
            sock.close()
        except OSError:
            pass

    return results
