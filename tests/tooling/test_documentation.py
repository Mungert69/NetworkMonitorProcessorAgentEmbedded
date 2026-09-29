"""Keep the coding-agent documentation chain local and resolvable."""
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]


class DocumentationTests(unittest.TestCase):
    def test_local_links_in_agent_documentation_chain(self):
        documents = [
            ROOT / "AGENTS.md",
            ROOT / "README.md",
            *sorted((ROOT / "docs").rglob("*.md")),
            ROOT / "tests/integration/http_deadline/README.md",
        ]
        for document in documents:
            with self.subTest(document=document.relative_to(ROOT)):
                self.assertTrue(document.is_file())
            # These docs use inline Markdown links. External URLs are not fetched.
            for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", document.read_text()):
                url = urlsplit(target)
                if url.scheme or url.netloc:
                    continue
                destination = (document.parent / unquote(url.path)).resolve() if url.path else document
                with self.subTest(document=document.relative_to(ROOT), target=target):
                    self.assertTrue(destination.is_relative_to(ROOT),
                                    "Deployment documentation must not require a sibling checkout")
                    self.assertTrue(destination.exists(), "Broken local documentation link")


if __name__ == "__main__":
    unittest.main()
