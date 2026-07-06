#!/usr/bin/env python3
"""
t5_wizard.py -- state-driven progressive-disclosure provisioning wizard for the
Cisco 400G-XP-LC (T5) over TL1.  SELF-CONTAINED: stdlib only, no other files
needed, runs on Python 3.6+.
"""

import itertools
import os
import re
import socket
import time


# ===========================================================================
# CONFIG -- nodes
# ===========================================================================
class Node(object):
    def __init__(self, ip, tl1_port=3082, name=""):
        self.ip = ip
        self.tl1_port = tl1_port
        self.name = name


NODES = [
    Node(ip="10.252.254.77", name="NE-77"),
    Node(ip="10.252.254.74", name="NE-74"),
]


# ===========================================================================
# TL1 session (raw socket)
# ===========================================================================
class Tl1Error(Exception):
    pass


class Tl1Response(object):
    def __init__(self, ctag, completion, error_code="", raw=""):
        self.ctag = ctag
        self.completion = completion
        self.error_code = error_code
        self.raw = raw

    @property
    def ok(self):
        return self.completion in ("COMPLD", "PRTL")


_COMPLETION_RE = re.compile(r"^M\s+(\S+)\s+(COMPLD|DENY|PRTL|RTRV)\b", re.MULTILINE)
_ERRCODE_RE = re.compile(r"^\s+([A-Z]{4})\b", re.MULTILINE)


class TL1Session(object):
    def __init__(self, sock, read_timeout=30.0, idle_gap=0.4, logger=None):
        self._s = sock
        self.read_timeout = read_timeout
        self.idle_gap = idle_gap
        self._log = logger or (lambda *_: None)
        self._buf = ""
        self._s.settimeout(0.5)

    def send(self, command):
        if not command.rstrip().endswith(";"):
            command = command.rstrip() + ";"
        self._log(">>> " + command)
        self._s.sendall((command + "\r\n").encode("ascii", "replace"))

    def _recv(self):
        try:
            chunk = self._s.recv(8192)
        except socket.timeout:
            return ""
        except OSError:
            return ""
        return chunk.decode("ascii", "replace") if chunk else ""

    def read_response(self, ctag):
        comp_re = re.compile(
            r"^M\s+{}\s+(COMPLD|DENY|PRTL|RTRV)\b".format(re.escape(str(ctag))),
            re.MULTILINE)
        deadline = time.monotonic() + self.read_timeout
        block, self._buf = self._buf, ""
        while time.monotonic() < deadline:
            data = self._recv()
            if data:
                block += data
                if ";" in block and comp_re.search(block):
                    time.sleep(self.idle_gap)
                    block += self._recv()
                    return self._parse(block, ctag, comp_re)
            else:
                if block and ";" in block and comp_re.search(block):
                    return self._parse(block, ctag, comp_re)
                time.sleep(0.05)
        raise Tl1Error("timeout waiting for ctag={}\n{}".format(ctag, block))

    def _parse(self, block, ctag, comp_re):
        self._log(block.strip())
        m = comp_re.search(block) or _COMPLETION_RE.search(block)
        if not m:
            return Tl1Response(ctag=ctag, completion="", raw=block)
        completion = m.group(m.lastindex)
        err = ""
        if completion == "DENY":
            em = _ERRCODE_RE.search(block[m.end():])
            err = em.group(1) if em else ""
        return Tl1Response(ctag=ctag, completion=completion,
                           error_code=err, raw=block)


_ctag = itertools.count(1)


def next_ctag():
    return str(next(_ctag))


CARD_TYPE = "400G-XP-LC"
SLICE_TO_CLIENT = {1: 7, 2: 8, 3: 9, 4: 10}
_STATE_RE = re.compile(r"((?:IS|OOS)-[A-Z]+(?:,[A-Z]+)?)")


# ===========================================================================
# TL1 helpers
# ===========================================================================
def _run(sess, template):
    ctag = next_ctag()
    sess.send(template.replace("{c}", ctag))
    return sess.read_response(ctag)


def _open(node, uid, pid):
    sock = socket.create_connection((node.ip, node.tl1_port), timeout=20)
    sess = TL1Session(sock)
    if not _run(sess, "ACT-USER::{}:{{c}}::{}".format(uid, pid)).ok:
        sock.close()
        raise Tl1Error("login rejected")
    return sock, sess


def _state_of(resp):
    if not resp.ok:
        return None
    m = _STATE_RE.findall(resp.raw)
    return m[-1] if m else "present"


# ===========================================================================
# Live state model
# ===========================================================================
class Port(object):
    def __init__(self, port, kind, optic=None, facility=None,
                 provisioned=False, state=None, freq=None):
        self.port = port
        self.kind = kind
        self.optic = optic
        self.facility = facility
        self.provisioned = provisioned
        self.state = state
        self.freq = freq


class Card(object):
    def __init__(self, shelf, slot, opmode="", trunkopmode="", clientsets="", ports=None):
        self.shelf = shelf
        self.slot = slot
        self.opmode = opmode
        self.trunkopmode = trunkopmode
        self.clientsets = clientsets
        self.ports = ports if ports is not None else []
        self.client_trunk = {}


def _optic_of(eqpt_raw, aid):
    for line in eqpt_raw.splitlines():
        if aid + ":" in line:
            m = re.search(r"(?<![A-Z])CARDNAME=([^,]+)", line)
            return m.group(1) if m else None
    return None


def discover(node, uid, pid):
    """Log in and build a live model of every 400G-XP-LC card on the node."""
    sock, sess = _open(node, uid, pid)
    try:
        eqpt = _run(sess, "RTRV-EQPT::ALL:{c}")
        clients_all = _run(sess, "RTRV-100GIGE::ALL:{c}")
        slots = sorted(set(re.findall(
            r"SLOT-(\d+)-(\d+):" + re.escape(CARD_TYPE), eqpt.raw)),
            key=lambda t: (int(t[0]), int(t[1])))
        cards = []
        for sh, sl in slots:
            sh, sl = int(sh), int(sl)
            opm = _run(sess, "RTRV-OPMODE::SLOT-{}-{}:{{c}}".format(sh, sl))
            mode = re.search(r"OPMODE=([^,]+)", opm.raw)
            top = re.search(r"TRUNKOPMODE=([^,]+)", opm.raw)
            cset = re.search(r"CLIENTSETS=([^,]+)", opm.raw)
            card = Card(shelf=sh, slot=sl,
                        opmode=mode.group(1) if mode else "",
                        trunkopmode=top.group(1) if top else "",
                        clientsets=cset.group(1) if cset else "")
            for tk, sn in re.findall(r"(\d+)/S(\d+)/", card.clientsets):
                cp = SLICE_TO_CLIENT.get(int(sn))
                if cp:
                    card.client_trunk[cp] = int(tk)
            trunk_ports = [int(p) for p in re.findall(r"(\d+)/", card.trunkopmode)]
            for p in sorted(set(trunk_ports)):
                aid = "VFAC-{}-{}-{}-1".format(sh, sl, p)
                fac = _run(sess, "RTRV-OTU4C2::{}:{{c}}".format(aid))
                freq = re.search(r"FREQ=([^,]+)", fac.raw)
                card.ports.append(Port(
                    port=p, kind="trunk",
                    optic=_optic_of(eqpt.raw, "PPM-{}-{}-{}".format(sh, sl, p)),
                    facility=aid, provisioned=fac.ok, state=_state_of(fac),
                    freq=freq.group(1) if freq else None))
            n_slices = len(re.findall(r"/S\d+/", card.clientsets)) or len(SLICE_TO_CLIENT)
            client_ports = [SLICE_TO_CLIENT[i] for i in range(1, n_slices + 1)
                           if i in SLICE_TO_CLIENT]
            for p in client_ports:
                aid = "AGGR-{}-{}-{}-1".format(sh, sl, p)
                provisioned = clients_all.ok and (aid + ":") in clients_all.raw
                state = None
                if provisioned:
                    for line in clients_all.raw.splitlines():
                        if aid + ":" in line:
                            mm = _STATE_RE.findall(line)
                            state = mm[-1] if mm else "present"
                            break
                card.ports.append(Port(
                    port=p, kind="client",
                    optic=_optic_of(eqpt.raw, "APPM-{}-{}-{}".format(sh, sl, p)),
                    facility=aid, provisioned=provisioned, state=state))
            cards.append(card)
        _run(sess, "CANC-USER::{}:{{c}}".format(uid))
        return cards
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ===========================================================================
# Decision core: which actions are legal for a port RIGHT NOW
# ===========================================================================
def _is_up(state):
    return bool(state) and state.startswith("IS")


def available_actions(port):
    if not port.optic and port.kind == "client":
        return []
    acts = []
    if port.kind == "client":
        if not port.provisioned:
            acts.append(("build", "Build up (create 100GIGE + power up)", False))
        elif _is_up(port.state):
            acts.append(("down", "Power down (OOS)", True))
            acts.append(("teardown", "Tear down (OOS + delete facility)", True))
        else:
            acts.append(("up", "Power up (bring IS)", False))
            acts.append(("teardown", "Tear down (delete facility)", True))
    else:  # trunk
        if _is_up(port.state):
            acts.append(("down", "Power down (OOS)", True))
        else:
            acts.append(("setfreq", "Set wavelength / frequency", False))
            acts.append(("up", "Power up (bring IS)", False))
    return acts


# ===========================================================================
# Apply handlers
# ===========================================================================
def _apply_client(sess, port, key, freq=None):
    aid = port.facility
    if key == "build":
        if not _run(sess, "ENT-100GIGE::{}:{{c}}:::NUMOFLANES=4".format(aid)).ok:
            return False
        _run(sess, "ED-100GIGE::{}:{{c}}::::IS".format(aid))
        return _verify(sess, "RTRV-100GIGE::{}:{{c}}".format(aid), "IS")
    if key == "up":
        _run(sess, "ED-100GIGE::{}:{{c}}::::IS".format(aid))
        return _verify(sess, "RTRV-100GIGE::{}:{{c}}".format(aid), "IS")
    if key == "down":
        _run(sess, "ED-100GIGE::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(aid))
        return _verify(sess, "RTRV-100GIGE::{}:{{c}}".format(aid), "OOS")
    if key == "teardown":
        _run(sess, "ED-100GIGE::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(aid))
        _run(sess, "DLT-100GIGE::{}:{{c}}".format(aid))
        return not _run(sess, "RTRV-100GIGE::{}:{{c}}".format(aid)).ok
    return False


def _apply_trunk(sess, port, key, freq=None):
    aid = port.facility
    if key == "setfreq":
        _run(sess, "ED-OTU4C2::{}:{{c}}:::FREQ={}".format(aid, freq))
        return True
    if key == "up":
        _run(sess, "ED-OTU4C2::{}:{{c}}::::IS".format(aid))
        return _verify(sess, "RTRV-OTU4C2::{}:{{c}}".format(aid), "IS")
    if key == "down":
        _run(sess, "ED-OTU4C2::{}:{{c}}:::CMDMDE=FRCD:OOS,DSBLD".format(aid))
        return _verify(sess, "RTRV-OTU4C2::{}:{{c}}".format(aid), "OOS")
    return False


def _verify(sess, rtrv_template, want):
    resp = _run(sess, rtrv_template)
    return resp.ok and want in resp.raw


# ===========================================================================
# Guided build helpers
# ===========================================================================
def _guided_run(sess, template, verify_template=None, want=None, tolerate=()):
    resp = _run(sess, template)
    if not resp.ok and resp.error_code not in tolerate:
        return False, "DENIED " + (resp.error_code or "?")
    if verify_template:
        v = _run(sess, verify_template)
        if not (v.ok and (want in v.raw if want else True)):
            return False, "verify failed"
    return True, "ok"
