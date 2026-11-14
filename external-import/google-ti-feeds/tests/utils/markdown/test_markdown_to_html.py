"""Tests for the conversion of GTI text fields to HTML."""

import pytest
from connector.src.utils.markdown_to_html import is_html, markdown_to_html


@pytest.mark.parametrize(
    "html",
    [
        "<p>First</p>\n\n    <p>Second</p>",
        "<div><h1>Title</h1><p>Body</p></div>",
    ],
)
def test_html_is_kept_as_is(html: str) -> None:
    """HTML is not converted, so indented tags are not turned into code blocks."""
    # Given HTML content
    # When it is converted
    # Then it is unchanged
    assert markdown_to_html(html) == html  # noqa: S101


def test_markdown_table_is_converted() -> None:
    """Markdown tables are rendered as HTML tables."""
    # Given a Markdown table
    text = "| a | b |\n|---|---|\n| 1 | 2 |"
    # When it is converted
    html = markdown_to_html(text)
    # Then it is an HTML table
    assert html.startswith("<table>")  # noqa: S101
    assert "<td>2</td>" in html  # noqa: S101


def test_html_with_markdown_is_converted() -> None:
    """Markdown inside HTML-wrapped content is still converted."""
    # Given HTML-wrapped content with a Markdown heading
    text = "<p>Intro</p>\n\n## Details\n\n<p>End</p>"
    # When it is converted
    # Then the heading is rendered
    assert "<h2>Details</h2>" in markdown_to_html(text)  # noqa: S101
    assert not is_html(text)  # noqa: S101


@pytest.mark.parametrize("text", [None, "", "   "])
def test_empty_text(text: str | None) -> None:
    """Empty text gives an empty string."""
    # Given empty text
    # When it is converted
    # Then the result is empty
    assert markdown_to_html(text) == ""  # noqa: S101
