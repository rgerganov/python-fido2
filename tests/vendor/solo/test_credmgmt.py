import pytest
from fido2.ctap2 import CredentialManagement
from tests.utils import *


@pytest.fixture(scope="module", params=["123456"])
def PinToken(request, device):
    device.reset()
    pin = request.param
    device.client.pin_protocol.set_pin(pin)
    return device.client.pin_protocol.get_pin_token(pin)


@pytest.fixture(scope="module")
def MC_RK_Res(device, PinToken):
    req = FidoRequest()
    pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
    rp = {"id": "ssh:", "name": "Bate Goiko"}
    req = FidoRequest(
        request=None, pin_protocol=1, pin_auth=pin_auth, rp=rp, options={"rk": True},
    )
    device.sendMC(*req.toMC())

    req = FidoRequest()
    pin_auth = hmac_sha256(PinToken, req.cdh)[:16]
    rp = {"id": "xakcop.com", "name": "John Doe"}
    req = FidoRequest(
        request=None, pin_protocol=1, pin_auth=pin_auth, rp=rp, options={"rk": True},
    )
    device.sendMC(*req.toMC())


@pytest.fixture(scope="module")
def CredMgmt(device, PinToken):
    pin_protocol = 1
    return CredentialManagement(device.ctap2, pin_protocol, PinToken)


class TestCredentialManagement(object):
    def test_get_metadata_one(self, CredMgmt, MC_RK_Res):
        metadata = CredMgmt.get_metadata()
        assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
        assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == 48

    def test_enumerate_rps(self, CredMgmt, MC_RK_Res):
        res = CredMgmt.enumerate_rps()
        assert len(res) == 2
        assert res[0][CredentialManagement.RESULT.RP]["id"] == "ssh:"
        assert res[0][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"ssh:")
        # Solo doesn't store rpId with the exception of "ssh:"
        assert res[1][CredentialManagement.RESULT.RP]["id"] == ""
        assert res[1][CredentialManagement.RESULT.RP_ID_HASH] == sha256(b"xakcop.com")

    def test_enumarate_creds(self, CredMgmt, MC_RK_Res):
        res = CredMgmt.enumerate_creds(sha256(b"ssh:"))
        assert len(res) == 1
        res = CredMgmt.enumerate_creds(sha256(b"xakcop.com"))
        assert len(res) == 1
        res = CredMgmt.enumerate_creds(sha256(b"missing.com"))
        assert not res
