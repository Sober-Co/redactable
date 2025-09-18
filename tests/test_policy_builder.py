from redactable.policy import PolicyBuilder, PolicyFactory


def test_policy_builder_creates_expected_policy():
    builder = PolicyBuilder(name="custom", version=2, description="Demo policy")
    builder.redact("email", replacement="<hidden email>")
    builder.mask("credit_card", keep_tail=2, mask_glyph="*")
    builder.tokenize("phone", salt="pepper", id="tokenize-phone")

    policy = builder.build()

    assert policy.name == "custom"
    assert policy.version == 2
    assert policy.description == "Demo policy"
    assert [rule.action for rule in policy.rules] == ["redact", "mask", "tokenize"]
    assert policy.rules[0].replacement == "<hidden email>"
    assert policy.rules[1].mask_glyph == "*"
    assert policy.rules[2].salt == "pepper"
    assert policy.rules[2].id == "tokenize-phone"


def test_policy_factory_recreates_rules():
    factory = PolicyFactory(
        name="factory",
        rules=(
            {"field": "email", "action": "redact", "replacement": "[secure]"},
            {"field": "credit_card", "action": "mask", "keep_head": 2},
        ),
    )

    policy_one = factory()
    policy_two = factory()

    assert policy_one.name == "factory"
    assert len(policy_one.rules) == 2
    assert policy_one.rules[0].replacement == "[secure]"

    # Different instances should be produced each time (no shared list)
    policy_one.rules[0].replacement = "changed"
    assert policy_two.rules[0].replacement == "[secure]"
