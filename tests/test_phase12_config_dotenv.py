import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from dotenv import load_dotenv

from sec_agent.config import Settings
from sec_agent.eval.preflight import run_preflight


class TestPhase12ConfigDotenv(unittest.TestCase):
    def test_dotenv_loads_settings_without_exposing_secrets(self) -> None:
        tracked = ("SUBQ_API_KEY", "GEMINI_API_KEY", "USE_MOCK_MODELS")
        saved = {k: os.environ.get(k) for k in tracked}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                env_file = Path(tmp) / ".env"
                env_file.write_text(
                    "SUBQ_API_KEY=sk-dummy-dotenv-secret-9999\n"
                    "GEMINI_API_KEY=AIzaDummyDotenvSecret8888\n"
                    "USE_MOCK_MODELS=false\n",
                    encoding="utf-8",
                )
                loaded = load_dotenv(dotenv_path=env_file, override=True)
                self.assertTrue(loaded)

                cfg = Settings()
                self.assertEqual(cfg.subq_api_key, "sk-dummy-dotenv-secret-9999")
                self.assertEqual(cfg.gemini_api_key, "AIzaDummyDotenvSecret8888")
                self.assertFalse(cfg.use_mock_models)

                report = asyncio.run(run_preflight(settings=cfg, check_network=False))
                serialized = json.dumps(report)
                self.assertNotIn("sk-dummy-dotenv-secret-9999", serialized)
                self.assertNotIn("AIzaDummyDotenvSecret8888", serialized)
                self.assertTrue(report["config"]["subq_api_key"].startswith("configured"))
                self.assertTrue(report["config"]["gemini_api_key"].startswith("configured"))
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
