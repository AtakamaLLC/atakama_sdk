# SPDX-FileCopyrightText: © Atakama, Inc <support@atakama.com>
# SPDX-License-Identifier: LGPL-3.0-or-later

import json
from multiprocessing.pool import ThreadPool

import yaml

from atakama import (
    RulePlugin,
    RuleSet,
    ApprovalRequest,
    RequestType,
    ProfileInfo,
    RuleEngine,
    RuleTree,
    MetaInfo,
)


class TestMetaInfo(MetaInfo):
    def __init__(self, meta="/meta", complete=True):
        super().__init__(meta=meta, complete=complete)


class TestProfileInfo(ProfileInfo):
    def __init__(self, profile_id=b"pid", profile_words=None):
        profile_words = profile_words or [
            "w1",
            "w2",
            "w3",
            "w4",
            "w5",
            "w6",
            "w7",
            "w8",
        ]
        super().__init__(profile_id=profile_id, profile_words=profile_words)


class TestApprovalRequest(ApprovalRequest):
    def __init__(
        self,
        request_type=RequestType.DECRYPT,
        device_id=b"did",
        profile=TestProfileInfo(),
        auth_meta=None,
    ):
        auth_meta = auth_meta or [TestMetaInfo()]
        super().__init__(
            request_type=request_type,
            device_id=device_id,
            profile=profile,
            auth_meta=auth_meta,
            cryptographic_id=b"cid",
        )


def test_simple_rule():
    # we just test that we can write a class to spec
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example"

        def approve_request(self, request):
            if request.device_id == b"3":
                return True
            return False

    rs = RuleSet([ExampleRule({"rule_id": "rid"})])

    assert rs.approve_request(TestApprovalRequest(device_id=b"3"))
    assert not rs.approve_request(TestApprovalRequest(device_id=b"4"))


def test_errs():
    # we just test that we can write a class to spec
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example"

        def approve_request(self, request):
            if request.device_id == b"3":
                return True
            if request.device_id == b"b":
                raise ValueError
            return None

    rs = RuleSet([ExampleRule({"rule_id": "rid"})])

    assert rs.approve_request(TestApprovalRequest(device_id=b"3"))
    assert rs.approve_request(TestApprovalRequest(device_id=b"4")) is False
    assert rs.approve_request(TestApprovalRequest(device_id=b"b")) is False


def test_simple_loader(tmp_path):
    # noinspection PyUnusedLocal
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example_loader"

        def __init__(self, args):
            self.okid = bytes.fromhex(args["device_id"])
            super().__init__(args)

        def approve_request(self, request):
            if request.device_id == self.okid:
                return True
            return False

    rule_yml = tmp_path / "rules.yml"
    info = {
        RequestType.DECRYPT.value: [
            [{"rule": "example_loader", "device_id": b"okdid".hex()}]
        ]
    }
    with rule_yml.open("w") as f:
        yaml.safe_dump(info, f)

    rs = RuleEngine.from_yml_file(rule_yml)

    assert rs.approve_request(TestApprovalRequest(device_id=b"okdid"))
    assert not rs.approve_request(TestApprovalRequest(device_id=b"whatever"))


def test_more_complex(tmp_path):
    # noinspection PyUnusedLocal
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "complex"

        def approve_request(self, request):
            did = bytes.fromhex(self.args.get("device_id", ""))
            meta = self.args.get("path", "")
            if did:
                return request.device_id == did
            if meta:
                return request.auth_meta[0].meta == meta

    rule_yml = tmp_path / "rules.yml"
    info = {
        RequestType.DECRYPT.value: [
            [
                {"rule": "complex", "device_id": b"okwmeta".hex()},
                {"rule": "complex", "path": "/meta"},
            ],
            [{"rule": "complex", "device_id": b"okany".hex()}],
        ],
        RequestType.SEARCH.value: [
            [
                {"rule": "complex", "device_id": b"okwmeta".hex()},
                {"rule": "complex", "path": "/search"},
            ],
            [{"rule": "complex", "device_id": b"okany".hex()}],
        ],
    }

    with rule_yml.open("w") as f:
        json.dump(info, f)

    rs = RuleEngine.from_yml_file(rule_yml)

    assert rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert rs.approve_request(
        TestApprovalRequest(device_id=b"okwmeta", auth_meta=[TestMetaInfo("/meta")])
    )
    assert rs.approve_request(
        TestApprovalRequest(
            request_type=RequestType.SEARCH,
            device_id=b"okwmeta",
            auth_meta=[TestMetaInfo("/search")],
        )
    )
    assert not rs.approve_request(
        TestApprovalRequest(device_id=b"okwmeta", auth_meta=[TestMetaInfo("/search")])
    )
    assert not rs.approve_request(
        TestApprovalRequest(request_type=RequestType.CREATE_PROFILE, device_id=b"okany")
    )
    assert not rs.approve_request(
        TestApprovalRequest(device_id=b"notok", auth_meta=[TestMetaInfo("/search")])
    )
    assert not rs.approve_request(
        TestApprovalRequest(device_id=b"notok", auth_meta=[TestMetaInfo("/meta")])
    )


def test_clear_quota():
    # we just test that we can write a class to spec
    class ExampleRule(RulePlugin):
        quota = {}

        @staticmethod
        def name():
            return "quota"

        def approve_request(self, request):
            self.quota[request.profile.profile_id] = (
                self.quota.get(request.profile.profile_id, 0) + 1
            )
            return self.quota[request.profile.profile_id] <= self.args["limit"]

        def clear_quota(self, profile: ProfileInfo) -> None:
            self.quota.pop(profile.profile_id, None)

        def at_quota(self, profile: ProfileInfo):
            assert profile.profile_id in self.quota, "exceptions == false"
            return self.quota[profile.profile_id] >= self.args["limit"]

    class ExampleOtherRule(RulePlugin):
        @staticmethod
        def name():
            return "other"

        def approve_request(self, request):
            return True

    rs = RuleSet(
        [ExampleRule({"limit": 2, "rule_id": "1"}), ExampleOtherRule({"rule_id": "2"})]
    )
    re = RuleEngine({RequestType.DECRYPT: RuleTree([rs])})

    # limit 2
    pi1 = TestProfileInfo(profile_id=b"pid1")
    pi2 = TestProfileInfo(profile_id=b"pid2")
    ar1 = TestApprovalRequest(profile=pi1)
    ar2 = TestApprovalRequest(profile=pi2)

    assert not re.at_quota(pi1)

    assert re.approve_request(ar1)
    assert re.approve_request(ar1)

    assert re.at_quota(pi1)
    assert not re.at_quota(pi2)

    assert not re.approve_request(ar1)

    # second pid limit 2
    assert re.approve_request(ar2)
    assert re.approve_request(ar2)
    assert not re.approve_request(ar2)

    re.clear_quota(pi1)

    # other request types are ignored, and don't impact quota
    assert (
        re.approve_request(
            TestApprovalRequest(
                request_type=RequestType.SEARCH,
                profile=pi1,
            )
        )
        is None
    )
    assert (
        re.approve_request(
            TestApprovalRequest(
                request_type=RequestType.SEARCH,
                profile=pi1,
            )
        )
        is None
    )
    assert (
        re.approve_request(
            TestApprovalRequest(
                request_type=RequestType.SEARCH,
                profile=pi1,
            )
        )
        is None
    )

    # pid 1 is still clear
    assert re.approve_request(ar1)

    # pid 2 is not
    assert not re.approve_request(ar2)


def test_rule_id_loads(tmp_path):
    # noinspection PyUnusedLocal
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "example_loader"

        def __init__(self, args):
            super().__init__(args)

        def approve_request(self, request):
            return True

    rule_yml = tmp_path / "rules.yml"
    info = {
        RequestType.DECRYPT.value: [
            [{"rule": "example_loader"}],
            [{"rule": "example_loader"}],
            [{"rule": "example_loader", "rule_id": "my_id"}],
        ]
    }
    with rule_yml.open("w") as f:
        yaml.safe_dump(info, f)

    re = RuleEngine.from_yml_file(rule_yml)

    expect = {
        RequestType.DECRYPT.value: [
            [{"rule": "example_loader", "rule_id": "74f7d0d4f50171df97b517416ac46df2"}],
            [
                {
                    "rule": "example_loader",
                    "rule_id": "74f7d0d4f50171df97b517416ac46df2.2",
                }
            ],
            [{"rule": "example_loader", "rule_id": "my_id"}],
        ]
    }
    assert re.to_dict() == expect


def test_rule_ordering(tmp_path):
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "exrule"

        def approve_request(self, request):
            if "target" in self.args:
                return approve_target
            return approve_other

        def use_quota(self, request):
            nonlocal used
            if "target" in self.args:
                used += 1
                if throw:
                    raise Exception("exc")

    approve_target, approve_other, throw = False, False, False
    used = 0
    rule_yml = tmp_path / "rules.yml"

    info = {
        RequestType.DECRYPT.value: [
            [
                {"rule": "exrule", "target": "yes"},
                {"rule": "exrule"},
            ],
        ],
    }
    with rule_yml.open("w") as f:
        json.dump(info, f)
    rs = RuleEngine.from_yml_file(rule_yml)

    # Failure in either rule in ruleset
    approve_target = True
    approve_other = False
    assert not rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert used == 0

    approve_target = False
    approve_other = True
    assert not rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert used == 0

    # Both approve
    approve_target = True
    approve_other = True
    assert rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert used == 1

    # The first rule set to approve is the one that's used
    info = {
        RequestType.DECRYPT.value: [
            [
                {"rule": "exrule", "target": "yes"},
            ],
            [
                {"rule": "exrule"},
            ],
        ],
    }
    with rule_yml.open("w") as f:
        json.dump(info, f)
    rs = RuleEngine.from_yml_file(rule_yml)
    assert rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert used == 2

    info = {
        RequestType.DECRYPT.value: [
            [
                {"rule": "exrule"},
            ],
            [
                {"rule": "exrule", "target": "yes"},
            ],
        ],
    }
    with rule_yml.open("w") as f:
        json.dump(info, f)
    rs = RuleEngine.from_yml_file(rule_yml)
    assert rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert used == 2

    # Skipping from first failed rule set to second
    approve_other = False
    rs = RuleEngine.from_yml_file(rule_yml)
    assert rs.approve_request(TestApprovalRequest(device_id=b"okany"))
    assert used == 3

    # Exception in rule use
    throw = True
    assert not rs.approve_request(TestApprovalRequest(device_id=b"okany"))


def test_atomic_ruleset_evaluation(tmp_path):
    class ExampleRule(RulePlugin):
        @staticmethod
        def name():
            return "exrule"

        def approve_request(self, request):
            return used < 50

        def use_quota(self, request):
            nonlocal used
            used += 1

    used = 0
    approvals = 0
    rule_yml = tmp_path / "rules.yml"
    info = {
        RequestType.DECRYPT.value: [
            [
                {"rule": "exrule"},
            ],
        ],
    }
    with rule_yml.open("w") as f:
        json.dump(info, f)
    rs = RuleEngine.from_yml_file(rule_yml)

    def make_req(_):
        nonlocal approvals
        if rs.approve_request(TestApprovalRequest(device_id=b"okany")):
            approvals += 1

    thread_pool = ThreadPool(10)
    thread_pool.map(make_req, range(100))

    assert used == 50
    assert approvals == 50
