"""The no-default-route check, which now verifies egress instead of inferring it."""

from unittest import mock

from honeypot.security.breakout import BreakoutPrevention

HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
INTERNAL_ONLY = HEADER + "eth0\t0043A8AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
WITH_DEFAULT = INTERNAL_ONLY + "eth1\t00000000\t01421EAC\t0003\t0\t0\t0\t00000000\n"


def _check(routes: str, reachable: bool):
    warnings: list[str] = []
    with mock.patch("builtins.open", mock.mock_open(read_data=routes)), mock.patch.object(
        BreakoutPrevention, "_egress_reachable", return_value=reachable
    ) as probe:
        ok = BreakoutPrevention._check_no_default_route(warnings)
    return ok, warnings, probe


def test_no_default_route_passes_without_probing():
    ok, warnings, probe = _check(INTERNAL_ONLY, reachable=True)
    assert ok and not warnings
    probe.assert_not_called()


def test_default_route_with_egress_blocked_passes():
    ok, warnings, _ = _check(WITH_DEFAULT, reachable=False)
    assert ok and not warnings


def test_default_route_with_open_egress_fails():
    ok, warnings, _ = _check(WITH_DEFAULT, reachable=True)
    assert not ok
    assert "egress is not blocked" in warnings[0]
