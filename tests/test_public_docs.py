import re
import unittest
from pathlib import Path
from xml.etree import ElementTree

from src.tool_profiles import known_tool_names


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PUBLIC_MARKDOWN = (
    README,
    ROOT / "CODE_OF_CONDUCT.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "docs" / "TOOL_REFERENCE.md",
    ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.md",
    ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.md",
    ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
)


class PublicDocumentationTests(unittest.TestCase):
    def test_readme_links_images_languages_and_tool_names_are_consistent(self):
        text = README.read_text(encoding="utf-8")
        self.assertEqual(text.count("```") % 2, 0, "unbalanced Markdown fences")
        self.assertNotIn("\ufffd", text)
        self.assertEqual(text.count('<a name="en"></a>'), 1)
        self.assertEqual(text.count('<a name="ru"></a>'), 1)

        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
            local = target.split("#", 1)[0]
            if local and not re.match(r"^[a-z]+://", local):
                self.assertTrue((ROOT / local).exists(), f"broken local link: {target}")
        for target in re.findall(r'<img\s+src="([^"]+)"', text):
            image = ROOT / target
            self.assertTrue(image.is_file(), f"missing README image: {target}")
            if image.suffix.casefold() == ".svg":
                ElementTree.parse(image)

        english, russian = text.split('<a name="ru"></a>', 1)
        catalog = set(known_tool_names())
        pattern = r"`([A-Z][A-Za-z0-9_]+)`"
        english_tools = set(re.findall(pattern, english)) & catalog
        russian_tools = set(re.findall(pattern, russian)) & catalog
        self.assertEqual(english_tools, russian_tools)
        self.assertGreaterEqual(len(english_tools), 30)

    def test_all_public_markdown_is_clean_and_local_links_resolve(self):
        forbidden_topics = ("vmprotect", "themida")
        for path in PUBLIC_MARKDOWN:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\ufffd", text, f"invalid UTF-8 replacement in {path}")
            self.assertEqual(
                text.count("```") % 2,
                0,
                f"unbalanced Markdown fences in {path}",
            )
            lowered = text.casefold()
            for topic in forbidden_topics:
                self.assertNotIn(topic, lowered, f"stale public topic in {path}: {topic}")
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
                local = target.split("#", 1)[0]
                if not local or re.match(r"^[a-z]+://", local):
                    continue
                resolved = (path.parent / local).resolve()
                self.assertTrue(resolved.exists(), f"broken local link in {path}: {target}")

    def test_public_setup_has_no_checkout_or_installation_specific_paths(self):
        paths = (
            README,
            ROOT / "CONTRIBUTING.md",
            ROOT / ".github" / "workflows" / "release.yml",
            ROOT / "tools" / "build_managed_probe.ps1",
            ROOT / "src" / "runtime_sections" / "60_evidence_and_managed.py",
        )
        forbidden = (
            r"C:\ai_slop",
            r"D:\PROJECTS",
            r"C:\Users\rison",
            r"C:\Tools\x64dbg-mcp",
            r"C:\x64dbg",
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for value in forbidden:
                self.assertNotIn(value, text, f"machine-specific path in {path.name}: {value}")


if __name__ == "__main__":
    unittest.main()
