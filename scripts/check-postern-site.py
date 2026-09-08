"""Check the complete static site's actual link graph and required assets using stdlib only."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import re

ROOT = Path(__file__).resolve().parents[1] / 'apps' / 'site'


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.ids = set()
        self.refs = []
        self.headings = 0
        self.lang = None
        self.description = False
        self.viewport = False
        self.title = False
        self.csp = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if 'id' in attrs:
            assert attrs['id'] not in self.ids, f'{self.path}: duplicate ID {attrs["id"]}'
            self.ids.add(attrs['id'])
        if tag == 'html':
            self.lang = attrs.get('lang')
        if tag == 'h1':
            self.headings += 1
        if tag == 'title':
            self.title = True
        if tag == 'meta':
            self.description |= attrs.get('name') == 'description' and bool(attrs.get('content'))
            self.viewport |= attrs.get('name') == 'viewport'
            self.csp |= attrs.get('http-equiv', '').lower() == 'content-security-policy'
        if tag == 'img':
            assert 'alt' in attrs, f'{self.path}: image missing alt'
            assert 'width' in attrs and 'height' in attrs, f'{self.path}: image missing dimensions'
        if tag in ('a', 'link') and 'href' in attrs:
            self.refs.append(attrs['href'])
        if tag in ('img', 'script') and 'src' in attrs:
            self.refs.append(attrs['src'])


documents = {}
for path in ROOT.glob('*.html'):
    document = Document(path)
    document.feed(path.read_text())
    assert document.lang == 'en', f'{path}: English language declaration required'
    assert document.headings == 1, f'{path}: expected one primary heading'
    assert document.description and document.viewport and document.title and document.csp, f'{path}: missing metadata'
    documents[path.resolve()] = document

assert len(documents) >= 8, 'Expected homepage, six reference pages, and 404'
for path, document in documents.items():
    for ref in document.refs:
        parts = urlsplit(ref)
        assert parts.scheme in ('', 'https', 'mailto'), f'{path}: unsupported link scheme {ref}'
        if parts.scheme or parts.netloc:
            continue
        target = (ROOT / unquote(parts.path.lstrip('/'))) if parts.path.startswith('/') else (path.parent / unquote(parts.path)) if parts.path else path
        target = target.resolve()
        assert target.is_relative_to(ROOT.resolve()), f'{path}: reference escapes document root'
        assert target.is_file(), f'{path}: missing target {ref}'
        if parts.fragment and target in documents:
            assert unquote(parts.fragment) in documents[target].ids, f'{path}: missing fragment {ref}'

supply = (ROOT / 'supply.html').read_text()
amounts = [int(value.replace(',', '')) for value in re.findall(r'<td class="numeric-cell">([\d,]+)</td>', supply)]
assert len(amounts) == 8 and sum(amounts[:-1]) == amounts[-1] == 100_000_000_000, 'Allocation values do not sum to the cap'
assert (ROOT / 'assets/quantum-lattice.webp').stat().st_size > 10_000, 'Missing hero artwork'
print(f'PASS: {len(documents)} HTML pages; {sum(len(d.refs) for d in documents.values())} references; assets, fragments, metadata, and supply allocations.')
