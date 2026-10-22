import unittest

from hermes_matrix_oidc.lifecycle import SyncAuthRetryBudget


class SyncAuthRetryBudgetTest(unittest.TestCase):
    def test_allows_only_one_refresh_until_a_successful_sync(self):
        budget = SyncAuthRetryBudget()

        self.assertTrue(budget.take())
        self.assertFalse(budget.take())
        budget.reset_after_success()
        self.assertTrue(budget.take())


if __name__ == "__main__":
    unittest.main()
