# [atakama](atakama.md).rule_engine
Atakama keyserver ruleset library


[(view source)](https://github.com/AtakamaLLC/atakama_sdk/blob/master/atakama/rule_engine.py)
## ApprovalRequest(object)

Rule engine plugins receive this object upon request.

Members:
 - request_type: RequestType
 - device_id: bytes - *uuid for the device*
 - profile: ProfileInfo - *user profile uuid and verification words*
 - auth_meta: List[MetaInfo] - *typically a path to a file*
 - cryptographic_id: bytes - *uuid for the file or data object**




## MetaInfo(object)
MetaInfo(meta: str, complete: bool)



## ProfileInfo(object)
ProfileInfo(profile_id: bytes, profile_words: List[str])



## RequestType(Enum)
An enumeration.



## RuleEngine(object)
A collection of RuleTree objects for each possible request_type.

Given a request, will dispatch to the correct tree, and return the result.

If no tree is available, will return None, so the caller can determine the default.



#### .approve\_request(self, request: atakama.rule\_engine.ApprovalRequest) -> Optional[int]
Returns the associated ruleset id, if any ruleset matches.

#### .get\_rule\_set(self, rs\_id: int) -> atakama.rule\_engine.RuleSet
Given a ruleset id, return the associated RuleSet.

Raises IndexError if not found.



## RulePlugin(Plugin)

Base class for key server approval rule handlers.

When a key server receives a request, rules are consulted for approval.

Each rule receives its configuration from the policy file,
not the atakama config, like other plugins.

In addition to standard arguments from the policy, file a unique
`rule_id` is injected, if not present.



#### .approve\_request(self, request: atakama.rule\_engine.ApprovalRequest) -> Optional[bool]

Return True if the request will be authorized.

Return False if the request is to be denied.
Raise None if the request type is unknown or invalid.
Exceptions and None are logged, and considered False.

This is called any time:
    a decryption agent wishes to decrypt a file.
    a decryption agent wishes to search a file.
    a decryption agent wishes to perform other multifactor request types.

See the RequestType class for more information.


#### .at\_quota(self, profile: atakama.rule\_engine.ProfileInfo) -> Optional[bool]

Returns True if the profile will not be approved in the next request.
Returns False if the profile *may* be approved for access, and is not past a limit.
Returns None if quotas are not used.

This is not a guarantee of future approval, it's a way of checking to see if any users have
reached any limits, quotas or other stateful things for reporting purposed.


#### .clear\_quota(self, profile: atakama.rule\_engine.ProfileInfo) -> None

Reset or clear any limits, quotas, access counts, bytes-transferred for a given profile.

Used by an administrator to "clear" or "reset" a user that has hit limits.


#### .use\_quota(self, request: atakama.rule\_engine.ApprovalRequest)

Given that a request has already been authorized via approve_request(), indicate
that this rule is being used for request approval and any internal counters
should be incremented.



## RuleSet(list)
A list of rules, can reply True, False, or None to an ApprovalRequest

All rules must pass in a ruleset

An empty ruleset always returns True



#### .approve\_request(self, request: atakama.rule\_engine.ApprovalRequest) -> bool
Return true if all rules return true.

#### .at\_quota(self, profile: atakama.rule\_engine.ProfileInfo) -> bool
Returns True if the given profile is at quota for any rule in the RuleSet.

#### .find\_rules(self, rule\_type: Type[atakama.rule\_engine.RulePlugin])
Given a rule engine class type, return the list of rules defined with that class.


## RuleTree(list)
A list of RuleSet objects.

Return the ruleset id if *any* RuleSet returns True.
Returns False if all RuleSets return False.



#### .approve\_request(self, request: atakama.rule\_engine.ApprovalRequest) -> Union[bool, int]
Return the ruleset id if any ruleset returns true, otherwise False.


