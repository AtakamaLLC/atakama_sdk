# SPDX-FileCopyrightText: © Atakama, Inc <support@atakama.com>
# SPDX-License-Identifier: LGPL-3.0-or-later

"""Atakama keyserver ruleset library"""
import abc
import hashlib
import json
import threading
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Union, TYPE_CHECKING, Optional, Any, Type
import logging

import yaml

from atakama import Plugin

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class RequestType(Enum):
    DECRYPT = "decrypt"
    SEARCH = "search"
    CREATE_PROFILE = "create_profile"
    CREATE_LOCATION = "create_location"
    RENAME = "rename"
    SECURE_EXPORT = "secure_export"
    START_SESSION = "start_session"


@dataclass
class ProfileInfo:
    profile_id: bytes
    """Requesting profile uuid"""
    profile_words: List[str]
    """Requesting profile 'words' mnemonic"""


@dataclass
class MetaInfo:
    meta: str
    """Typically the full mount-path of a file."""
    complete: bool
    """Whether the meta is complete (fully verified) or partial (missing components)"""


@dataclass
class ApprovalRequest:
    """
    Rule engine plugins receive this object upon request.

    Members:
     - request_type: RequestType
     - device_id: bytes - *uuid for the device*
     - profile: ProfileInfo - *user profile uuid and verification words*
     - auth_meta: List[MetaInfo] - *typically a path to a file*
     - cryptographic_id: bytes - *uuid for the file or data object**
    """

    request_type: RequestType
    device_id: bytes
    profile: ProfileInfo
    auth_meta: List[MetaInfo]
    cryptographic_id: bytes


class RulePlugin(Plugin):
    """
    Base class for key server approval rule handlers.

    When a key server receives a request, rules are consulted for approval.

    Each rule receives its configuration from the policy file,
    not the atakama config, like other plugins.

    In addition to standard arguments from the policy, file a unique
    `rule_id` is injected, if not present.
    """

    def __init__(self, args):
        super().__init__(args)
        self.rule_id = args["rule_id"]

    @abc.abstractmethod
    def approve_request(self, request: ApprovalRequest) -> Optional[bool]:
        """
        Return True if the request will be authorized.

        Return False if the request is to be denied.
        Raise None if the request type is unknown or invalid.
        Exceptions and None are logged, and considered False.

        This is called any time:
            a decryption agent wishes to decrypt a file.
            a decryption agent wishes to search a file.
            a decryption agent wishes to perform other multifactor request types.

        See the RequestType class for more information.
        """

    def use_quota(self, request: ApprovalRequest):
        """
        Given that a request has already been authorized via approve_request(), indicate
        that this rule is being used for request approval and any internal counters
        should be incremented.
        """

    def at_quota(self, profile: ProfileInfo) -> Optional[bool]:
        """
        Returns True if the profile will not be approved in the next request.
        Returns False if the profile *may* be approved for access, and is not past a limit.
        Returns None if quotas are not used.

        This is not a guarantee of future approval, it's a way of checking to see if any users have
        reached any limits, quotas or other stateful things for reporting purposed.
        """

    def clear_quota(self, profile: ProfileInfo) -> None:
        """
        Reset or clear any limits, quotas, access counts, bytes-transferred for a given profile.

        Used by an administrator to "clear" or "reset" a user that has hit limits.
        """

    @classmethod
    def from_dict(cls, data: dict) -> "RulePlugin":
        """
        Factory function called with a dict from the rules yaml file.
        """

        assert type(data) is dict, "Rule entries must be dicts"
        assert "rule" in data, "Rule entries must have a plugin name"
        pname = data.pop("rule")
        p = RulePlugin.get_by_name(pname)(data)
        assert isinstance(p, RulePlugin), "Rule plugins must derive from RulePlugin"
        return p

    def to_dict(self):
        out = self.args.copy()
        out["rule"] = self.name()
        return out


class RuleIdGenerator:
    """Manage unique rule id generation."""

    __autodoc__ = False

    def __init__(self):
        self._seen = defaultdict(lambda: 0)

    def generate(self, ent: Any) -> str:
        ent_data = json.dumps(ent, sort_keys=True, separators=(",", ":"))
        ent_hash = hashlib.md5(ent_data.encode("utf8")).hexdigest()
        # if the hash is enough, use it, that way it's relocatable and still consistent
        if ent_hash in self._seen:
            self._seen[ent_hash] += 1
            # otherwise append a sequence
            ent_hash += "." + str(self._seen[ent_hash])
        self._seen[ent_hash] += 1
        return ent_hash

    def inject_rule_id(self, ent: dict):
        """
        Modify the supplied dictionary to add a rule_id, but only if a rule_id is not present.

        Keeps track of rule id's and ensures uniqueness, while trying to maintain consistency.
        """

        rule_id = ent.get("rule_id")
        if not rule_id:
            ent_hash = self.generate(ent)
            ent["rule_id"] = ent_hash
        else:
            self._seen[ent["rule_id"]] += 1


class RuleSet(List[RulePlugin]):
    """A list of rules, can reply True, False, or None to an ApprovalRequest

    All rules must pass in a ruleset

    An empty ruleset always returns True
    """

    def __init__(self, *args, **kws):
        super().__init__(*args, **kws)

        self.__lock = threading.RLock()

    def approve_request(self, request: ApprovalRequest) -> bool:
        """Return true if all rules return true."""
        # Lock to prevent races between approve_request and use_quota
        with self.__lock:
            # Check if all rules approve
            for i, rule in enumerate(self):  # pylint: disable=not-an-iterable
                try:
                    res = rule.approve_request(request)
                    log.debug(
                        "RuleSet.approve_request[%s]: rule_id=%s i=%i res=%s",
                        request.request_type,
                        rule.rule_id,
                        i,
                        res,
                    )
                    if res is None:
                        log.error("unknown request type error in rule %s", rule)
                    if not res:
                        return False
                except Exception as ex:
                    log.error("error in rule %s: %s", rule, repr(ex))
                    return False

            # Rule set succeeded, so now inc the quota counts
            for i, rule in enumerate(self):  # pylint: disable=not-an-iterable
                try:
                    rule.use_quota(request)
                except Exception as ex:
                    log.error("error in rule use_quota %s: %s", rule, repr(ex))
                    return False
        return True

    @classmethod
    def from_list(cls, ruledata: List[dict], rgen: RuleIdGenerator) -> "RuleSet":
        lst = []
        assert isinstance(ruledata, list), "Rulesets must be lists"
        for ent in ruledata:
            rgen.inject_rule_id(ent)
            lst.append(RulePlugin.from_dict(ent))
        return RuleSet(lst)

    def to_list(self) -> List[Dict]:
        lst = []
        # https://github.com/PyCQA/pylint/issues/2568
        for ent in self:  # pylint: disable=not-an-iterable
            lst.append(ent.to_dict())
        return lst

    def at_quota(self, profile: ProfileInfo) -> bool:
        """Returns True if the given profile is at quota for any rule in the RuleSet."""
        for i, rule in enumerate(self):  # pylint: disable=not-an-iterable
            try:
                res = rule.at_quota(profile)
                if res:
                    log.debug(
                        "RuleSet.at_quota: is at quota rule_id=%s i=%i profile=%s",
                        rule.rule_id,
                        i,
                        profile.profile_id,
                    )
                    return True
            except Exception as ex:
                log.error("error in rule %s: %s", rule, repr(ex))
                continue
        return False

    def find_rules(self, rule_type: Type[RulePlugin]):
        """Given a rule engine class type, return the list of rules defined with that class."""
        ret = []
        for rule in self:  # pylint: disable=not-an-iterable
            if isinstance(rule, rule_type):
                ret.append(rule)
        return ret


class RuleTree(List[RuleSet]):
    """A list of RuleSet objects.

    Return the ruleset id if *any* RuleSet returns True.
    Returns False if all RuleSets return False.
    """

    def approve_request(self, request: ApprovalRequest) -> Union[bool, int]:
        """Return the ruleset id if any ruleset returns true, otherwise False."""
        for i, rset in enumerate(self):  # pylint: disable=not-an-iterable
            res = rset.approve_request(request)
            log.debug(
                "RuleTree.approve_request[%s]: set=%i res=%s",
                request.request_type,
                i,
                res,
            )
            if res:
                return id(rset)
        return False

    @classmethod
    def from_list(cls, ruledefs: List[List[dict]], rgen: RuleIdGenerator) -> "RuleTree":
        ini = []
        for ent in ruledefs:
            rset = RuleSet.from_list(ent, rgen)
            ini.append(rset)
        return RuleTree(ini)

    def to_list(self) -> List[List[Dict]]:
        lst = []
        for ent in self:  # pylint: disable=not-an-iterable
            lst.append(ent.to_list())
        return lst

    def at_quota(self, profile: ProfileInfo) -> bool:
        for rset in self:  # pylint: disable=not-an-iterable
            res = rset.at_quota(profile)
            if res:
                return True
        return False


class RuleEngine:
    """A collection of RuleTree objects for each possible request_type.

    Given a request, will dispatch to the correct tree, and return the result.

    If no tree is available, will return None, so the caller can determine the default.
    """

    def __init__(self, rule_map: Dict[RequestType, RuleTree]):
        self.map: Dict[RequestType, RuleTree] = rule_map

    def approve_request(self, request: ApprovalRequest) -> Optional[int]:
        """Returns the associated ruleset id, if any ruleset matches."""
        tree = self.map.get(request.request_type, None)
        if tree is None:
            log.debug(
                "RuleEngine.approve_request: no tree for type %s", request.request_type
            )
            return None
        return tree.approve_request(request)

    @classmethod
    def from_yml_file(cls, yml: Union["Path", str]):
        """Build a rule engine from a yml file, see `from_dict` for more info."""
        log.debug("from_yml_file loading %s", yml)
        with open(yml, "r", encoding="utf8") as fh:
            info: dict = yaml.safe_load(fh)
            return cls.from_dict(info)

    @classmethod
    def from_dict(
        cls, info: Dict[str, Union[Dict[str, Any], List[List[dict]]]]
    ) -> "RuleEngine":
        """Build a rule engine from a dictionary:

        Example:
        ```
        request_type:
          - - rule: name
              param: val1
            - rule: name2
              param: val2
          - - rule: name
              param: val1
        ```
        """
        rgen = RuleIdGenerator()
        rule_map = {}
        for rtype, treedef in info.items():
            rtype = RequestType(rtype)
            tree = RuleTree.from_list(treedef, rgen)
            rule_map[rtype] = tree
        return cls(rule_map)

    def clear_quota(self, profile: ProfileInfo):
        for rt in self.map.values():
            for rs in rt:
                for rule in rs:
                    rule.clear_quota(profile)

    def at_quota(self, profile: ProfileInfo) -> bool:
        seen = set()
        for tree in self.map.values():
            if not id(tree) in seen:
                if tree.at_quota(profile):
                    return True
                seen.add(id(tree))
        return False

    def to_dict(self) -> Dict[str, List[List[Dict]]]:
        dct = {}
        for req, ent in self.map.items():
            dct[req.value] = ent.to_list()
        return dct

    def get_rule_set(self, rs_id: int) -> RuleSet:
        """Given a ruleset id, return the associated RuleSet.

        Raises IndexError if not found.
        """
        for tree in self.map.values():
            for rset in tree:
                if id(rset) == rs_id:
                    return rset

        raise IndexError("invalid ruleset id")
