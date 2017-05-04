import unittest
import json
import handler

class TestHandler(unittest.TestCase):

    def test_validate(self):
        invalid_event_1 = ''
        invalid_event_2 = json.loads(
            '{"methodArn": "arn", "authorizationToken": "Malformed"}'
        )
        valid_event = json.loads(
            '{"methodArn": "arn", "authorizationToken": "Basic abc"}'
        )

        assert not handler.validate(invalid_event_1)
        assert not handler.validate(invalid_event_2)
        assert  handler.validate(valid_event)

    def test_gen_policy(self):
        allowing_policy = handler.gen_policy('principal', 'Allow', 'arn')
        denying_policy = handler.gen_policy('principal', 'Deny', 'arn')

        assert 'Allow' in allowing_policy['policyDocument']['Statement'][0]['Effect']
        assert 'Deny' in denying_policy['policyDocument']['Statement'][0]['Effect']
