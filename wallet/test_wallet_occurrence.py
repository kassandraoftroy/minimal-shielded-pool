"""Wallet reconstruction checks. Run: python3 wallet/test_wallet_occurrence.py."""
import unittest
from unittest.mock import patch

import gen_nonce_race as race
import wallet as w


class WalletOccurrenceTest(unittest.TestCase):
    POOL = "0x" + "12" * 20

    def rebuild(self, leaves, epoch=0, expected_epoch=None):
        tree = w.Tree()
        for cm in leaves:
            tree.append(cm)
        logs = [{"topics": [race.LEAF_APPENDED_TOPIC, hex(cm), hex(epoch)],
                 "data": "0x" + f"{index:064x}{tree.root():064x}"}
                for index, cm in enumerate(leaves)]
        # An older epoch's same index must not overwrite a current leaf.
        logs.append({"topics": [race.LEAF_APPENDED_TOPIC, hex(17), hex(epoch + 1)],
                     "data": "0x" + "0" * 128})

        def rpc(_url, method, params):
            if method == "eth_getLogs":
                return logs
            if params[0]["data"] == "0x76671808":
                return hex(epoch)
            return hex(tree.root())

        with patch.object(race, "_rpc", side_effect=rpc):
            return race.seeded_tree("test", self.POOL,
                                    epoch if expected_epoch is None else expected_epoch)

    def test_duplicate_events_remain_distinct_positions(self):
        cm = w.commitment(123, 456, 100)
        tree = self.rebuild([cm, cm])
        self.assertEqual(tree.leaves, [cm, cm])
        domain = w.domain_scalar(31337, self.POOL, 0)
        self.assertNotEqual(w.nullifier(domain, 123, cm, 0), w.nullifier(domain, 123, cm, 1))

    def test_reorg_rebuild_changes_position_and_spend_identity(self):
        cm = w.commitment(123, 456, 100)
        other = w.commitment(321, 654, 200)
        before = self.rebuild([cm, other])
        after = self.rebuild([other, cm])
        domain = w.domain_scalar(31337, self.POOL, 0)
        old_index, new_index = before.leaves.index(cm), after.leaves.index(cm)
        self.assertEqual((old_index, new_index), (0, 1))
        self.assertNotEqual(before.root(), after.root())
        self.assertNotEqual(w.nullifier(domain, 123, cm, old_index),
                            w.nullifier(domain, 123, cm, new_index))

    def test_later_root_keeps_existing_occurrence_identity(self):
        cm = w.commitment(123, 456, 100)
        before = self.rebuild([cm])
        after = self.rebuild([cm, w.commitment(321, 654, 200)])
        domain = w.domain_scalar(31337, self.POOL, 0)
        self.assertNotEqual(before.root(), after.root())
        self.assertEqual(w.nullifier(domain, 123, cm, before.leaves.index(cm)),
                         w.nullifier(domain, 123, cm, after.leaves.index(cm)))

    def test_epoch_mismatch_stops_before_proving(self):
        with self.assertRaisesRegex(SystemExit, "does not match the live tree epoch"):
            self.rebuild([w.commitment(123, 456, 100)], epoch=1, expected_epoch=0)

    def test_same_index_in_another_epoch_has_a_new_spend_identity(self):
        cm = w.commitment(123, 456, 100)
        epoch0 = self.rebuild([cm], epoch=0)
        epoch1 = self.rebuild([cm], epoch=1)
        self.assertEqual(epoch0.root(), epoch1.root())
        self.assertNotEqual(w.nullifier(w.domain_scalar(31337, self.POOL, 0), 123, cm, 0),
                            w.nullifier(w.domain_scalar(31337, self.POOL, 1), 123, cm, 0))


if __name__ == "__main__":
    unittest.main()
