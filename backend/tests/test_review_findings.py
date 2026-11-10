"""Regression tests for the findings of the independent review (2026-11-11)."""

import pickle

import pytest

from app.ai import provenance
from app.core import encryption
from app.core.encryption import ContextMismatch, blob_context, decrypt_data, encrypt_data, session_context
from app.schemas.ingest import SessionIngest
from app.tools.eval_pipeline import layer_report


# -- model files are signed ---------------------------------------------------

def test_a_model_file_is_loaded_only_with_this_deployments_signature(tmp_path):
    path = str(tmp_path / "model.pkl")
    provenance.dump_pickle(path, {"model": "m", "features": ["a"]})
    assert provenance.load_pickle(path) == {"model": "m", "features": ["a"]}

    # Replaced by something else, unsigned: what a swapped file looks like.
    with open(path, "wb") as handle:
        pickle.dump({"model": "other"}, handle)
    with pytest.raises(provenance.UntrustedModel):
        provenance.load_pickle(path)

    # Signed, then one byte of the model changed.
    provenance.dump_pickle(path, {"model": "m"})
    blob = bytearray(open(path, "rb").read())
    blob[-2] ^= 0x01
    open(path, "wb").write(bytes(blob))
    with pytest.raises(provenance.UntrustedModel):
        provenance.load_pickle(path)


def test_a_file_signed_under_another_key_is_refused_until_an_operator_signs_it(tmp_path, monkeypatch):
    path = str(tmp_path / "trained.pkl")
    monkeypatch.setattr(provenance, "_model_key", lambda: b"k" * 32)
    provenance.dump_pickle(path, {"model": "trained elsewhere"})
    monkeypatch.undo()
    with pytest.raises(provenance.UntrustedModel):
        provenance.load_pickle(path)
    provenance.sign_file(path)
    assert provenance.load_pickle(path) == {"model": "trained elsewhere"}


def test_an_unsigned_flow_model_is_neither_loaded_nor_overwritten(tmp_path, monkeypatch):
    from app.ai import classifier as module

    path = tmp_path / "random_forest_model.pkl"
    path.write_bytes(pickle.dumps({"model": "unsigned"}))
    before = path.read_bytes()
    monkeypatch.setattr(module.settings, "MODEL_PATH_RF", str(path))
    fresh = module.AttackClassifier()
    fresh._ensure_loaded()
    assert fresh.model_source == "synthetic"
    assert path.read_bytes() == before, "an untrusted model file must be left for the operator, not replaced"


# -- stored blobs are bound to their row and column ----------------------------

def test_strict_mode_refuses_an_unbound_blob_where_a_binding_is_expected(monkeypatch):
    bound = encrypt_data("secret", session_context(7, "credentials_encrypted"))
    unbound = encrypt_data("secret")
    with pytest.raises(ContextMismatch):
        decrypt_data(bound, session_context(7, "transcript_encrypted"))
    # By default an unbound blob written before binding existed still opens.
    assert decrypt_data(unbound, session_context(7, "transcript_encrypted")) == "secret"
    monkeypatch.setattr(encryption, "_require_context", lambda: True)
    with pytest.raises(ContextMismatch):
        decrypt_data(unbound, session_context(7, "transcript_encrypted"))
    assert decrypt_data(bound, session_context(7, "credentials_encrypted")) == "secret"


async def test_ingest_binds_each_blob_to_its_session_and_column(db_session):
    from app.models import HoneypotNode, HoneypotSession
    from app.services.analysis import analysis_pipeline
    from sqlalchemy import select

    node = HoneypotNode(name="review-node", protocol="ssh", ip_address="10.0.0.9", port=2222)
    db_session.add(node)
    await db_session.commit()
    await analysis_pipeline.process_session(db_session, {
        "protocol": "ssh", "attacker_ip": "45.83.64.9", "attacker_port": 40000,
        "commands": ["id"], "payload": "x",
        "transcript": [{"command": "id", "output": "uid=0", "exit_code": 0, "timestamp": 1.0}],
        "credentials": [{"username": "root", "password": "toor", "success": True}],
        "truncated": {"outputs": 3, "events": 0}, "threat_profile": "scripted",
    }, node.id)
    await db_session.commit()
    stored = (await db_session.execute(select(HoneypotSession))).scalar_one()
    for column in ("raw_commands_encrypted", "raw_payloads_encrypted", "transcript_encrypted", "credentials_encrypted"):
        assert blob_context(getattr(stored, column)) == session_context(stored.id, column)
    with pytest.raises(ContextMismatch):
        decrypt_data(stored.credentials_encrypted, session_context(stored.id, "transcript_encrypted"))
    # What the engine cut, and its profile, are no longer dropped.
    assert stored.signals["truncated"] == {"outputs": 3}
    assert stored.signals["engine_profile"] == "scripted"


# -- ingest schema -------------------------------------------------------------

def test_list_valued_and_long_fingerprints_survive_validation():
    payload = SessionIngest.model_validate({
        "protocol": "telnet", "attacker_ip": "45.83.64.9",
        "fingerprints": {
            "telnet_options": ["DO 1", "WILL 24", "WILL 31"],
            "hassh_algorithms": "a" * 1500,
            "empty": [], "nested": {"x": 1},
        },
    })
    kept = payload.to_pipeline()["fingerprints"]
    assert kept["telnet_options"] == "DO 1,WILL 24,WILL 31"
    assert len(kept["hassh_algorithms"]) == 1500
    assert "nested" not in kept and "empty" not in kept


# -- payload analysis stays out of the ingest role -------------------------------

async def test_the_ingest_role_leaves_samples_pending(monkeypatch):
    from app.services import payload_enrichment

    class Settings:
        PAYLOAD_ANALYSIS_ENABLED = True
        api_role = "ingest"

    monkeypatch.setattr(payload_enrichment, "get_settings", lambda: Settings())
    started = []
    monkeypatch.setattr(payload_enrichment, "_run_batch", lambda ids: started.append(ids))
    payload_enrichment.schedule([1, 2])
    assert started == [] and not payload_enrichment._in_flight


# -- evaluation tool -----------------------------------------------------------

def test_a_layer_that_answered_few_sessions_gets_no_headline():
    pairs = [("benign", "benign")] * 5 + [("benign", None)] * 95
    report = layer_report(pairs, headline=True, resamples=10, min_answered=50)
    assert report["coverage"] == 0.05
    assert "accuracy" not in report and "headline_withheld" in report
    full = layer_report([("benign", "benign")] * 60, headline=True, resamples=10, min_answered=50)
    assert full["accuracy"] == 1.0 and full["coverage"] == 1.0
