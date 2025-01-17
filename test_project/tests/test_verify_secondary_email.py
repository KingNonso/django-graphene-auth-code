from graphql_auth.constants import Messages
from graphql_auth.exceptions import EmailAlreadyInUseError
from graphql_auth.utils import get_token

from .base_test_case import BaseTestCase


class VerifySecondaryEmailBaseTestCase(BaseTestCase):
    def setUp(self):
        self.user = self.register_user(email="bar@email.com", username="bar", verified=True)
        self.user2 = self.register_user(email="foo@email.com", username="foo", verified=True)

    def get_verify_query(self, token):
        raise NotImplementedError

    def _test_verify_secondary_email(self):
        self.assertEqual(self.user.status.secondary_email, '')  # type: ignore
        secondary_email = 'new_email@email.com'
        token = get_token(
            self.user,
            "activation_secondary_email",
            secondary_email=secondary_email,
        )
        response = self.query(self.get_verify_query(token))
        self.assertResponseNoErrors(response)
        result = self.get_response_result(response)
        self.assertTrue(result['success'])
        self.user.status.refresh_from_db()  # type: ignore
        self.assertEqual(self.user.status.secondary_email, secondary_email)  # type: ignore

    def _test_invalid_token(self):
        response = self.query(self.get_verify_query('fake-token'))
        self.assertResponseNoErrors(response)
        result = self.get_response_result(response)
        self.assertFalse(result['success'])
        self.assertEqual(result['errors'], Messages.INVALID_TOKEN)

    def _test_email_in_use(self):
        token = get_token(self.user, "activation_secondary_email", secondary_email=self.user2.email)  # type: ignore
        response = self.query(self.get_verify_query(token))
        self.assertResponseNoErrors(response)
        result = self.get_response_result(response)
        self.assertFalse(result['success'])
        self.assertEqual(result['errors'], Messages.EMAIL_IN_USE)


class VerifySecondaryEmailCase(VerifySecondaryEmailBaseTestCase):
    RESPONSE_RESULT_KEY = 'verifySecondaryEmail'

    def get_verify_query(self, token):
        return """
        mutation {
            verifySecondaryEmail(token: "%s")
                { success, errors }
            }
        """ % (token)


class VerifySecondaryEmailRelayTestCase(VerifySecondaryEmailBaseTestCase):
    RESPONSE_RESULT_KEY = 'relayVerifySecondaryEmail'

    def get_verify_query(self, token):
        return """
        mutation {
        relayVerifySecondaryEmail(input:{ token: "%s"})
            { success, errors }
        }
        """ % (token)

