import copy
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_detection_promotion_matrix.py"
spec = importlib.util.spec_from_file_location("verify_detection_promotion_matrix", MODULE_PATH)
matrix = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(matrix)


class PromotionMatrixVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(ROOT / "detections", self.root / "detections")

    def tearDown(self):
        self.tmp.cleanup()

    @property
    def matrix_path(self):
        return self.root / "detections" / "DETECTION_PROMOTION_MATRIX.yml"

    def load_matrix(self):
        return yaml.safe_load(self.matrix_path.read_text(encoding="utf-8"))

    def write_matrix(self, data):
        self.matrix_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def test_valid_repository_matrix_passes(self):
        entries = matrix.verify_repo(self.root, print_summary=False)
        self.assertGreaterEqual(len(entries), 1)

    def test_malformed_matrix_fails(self):
        self.matrix_path.write_text("- not-a-mapping\n", encoding="utf-8")
        with self.assertRaises(matrix.MatrixError):
            matrix.verify_repo(self.root, print_summary=False)

    def test_duplicate_detection_id_fails(self):
        data = self.load_matrix()
        data["entries"].append(copy.deepcopy(data["entries"][0]))
        self.write_matrix(data)
        with self.assertRaises(matrix.MatrixError):
            matrix.verify_repo(self.root, print_summary=False)

    def test_missing_required_file_fails(self):
        data = self.load_matrix()
        entry = next(item for item in data["entries"] if item["detection_id"] == "HO-DET-013")
        entry["required_files"].append("missing-required-file.yml")
        self.write_matrix(data)
        with self.assertRaises(matrix.MatrixError):
            matrix.verify_repo(self.root, print_summary=False)

    def test_truthy_runtime_signal_or_public_safe_promotion_fails(self):
        for key, value in (
            ("runtime_active", True),
            ("signal_observed", "YES"),
            ("public_safe_status", "PUBLIC_SAFE"),
        ):
            with self.subTest(key=key):
                data = self.load_matrix()
                data["entries"][0][key] = value
                self.write_matrix(data)
                with self.assertRaises(matrix.MatrixError):
                    matrix.verify_repo(self.root, print_summary=False)
                self.write_matrix(self.load_matrix_from_repo())

    def test_package_tree_missing_from_matrix_fails(self):
        data = self.load_matrix()
        data["entries"] = [item for item in data["entries"] if item["detection_id"] != "HO-DET-013"]
        self.write_matrix(data)
        with self.assertRaises(matrix.MatrixError):
            matrix.verify_repo(self.root, print_summary=False)

    def test_source_index_missing_from_matrix_fails(self):
        data = self.load_matrix()
        data["entries"] = [item for item in data["entries"] if item["detection_id"] != "HO-DET-016"]
        self.write_matrix(data)
        with self.assertRaises(matrix.MatrixError):
            matrix.verify_repo(self.root, print_summary=False)

    def load_matrix_from_repo(self):
        return yaml.safe_load((ROOT / "detections" / "DETECTION_PROMOTION_MATRIX.yml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
