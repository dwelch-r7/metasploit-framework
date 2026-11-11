"""Independent phpinfo table decoding for native responses and actual loot files."""
from html.parser import HTMLParser
import json
from pathlib import Path
import sys

VARIABLES = ['OWNCLOUD_ADMIN_USERNAME', 'OWNCLOUD_ADMIN_PASSWORD', 'OWNCLOUD_DB_HOST',
             'OWNCLOUD_DB_USERNAME', 'OWNCLOUD_DB_PASSWORD', 'OWNCLOUD_DB_NAME', 'OWNCLOUD_DB_TYPE',
             'OWNCLOUD_MAIL_SMTP_HOST', 'OWNCLOUD_MAIL_SMTP_PORT', 'OWNCLOUD_MAIL_SMTP_NAME',
             'OWNCLOUD_MAIL_SMTP_PASSWORD', 'OWNCLOUD_REDIS_HOST', 'OWNCLOUD_REDIS_PORT',
             'OWNCLOUD_REDIS_PASSWORD', 'OWNCLOUD_REDIS_ENABLED', 'OWNCLOUD_LICENSE_KEY',
             'OWNCLOUD_OBJECTSTORE_KEY', 'OWNCLOUD_OBJECTSTORE_SECRET', 'OWNCLOUD_OBJECTSTORE_REGION',
             'OWNCLOUD_OBJECTSTORE_ENDPOINT', 'OWNCLOUD_OBJECTSTORE_BUCKET', 'OWNCLOUD_OBJECTSTORE_ENABLED']


class PhpInfo(HTMLParser):
    """Read complete decoded table cells, including PHP's italic empty sentinel."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.row, self.cell, self.empty, self.rows = [], None, False, {}

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self.row = []
        if tag in {'td', 'th'}:
            self.cell, self.empty = [], False
        if tag == 'i' and self.cell is not None:
            self.empty = True

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in {'td', 'th'} and self.cell is not None:
            self.row.append('' if self.empty else ''.join(self.cell).strip())
            self.cell = None
        if tag == 'tr' and len(self.row) == 2 and self.row[0] in VARIABLES:
            name, value = self.row
            assert self.rows.get(name, value) == value, name
            self.rows[name] = value



if __name__ == "__main__":
    parser = PhpInfo()
    parser.feed(Path(sys.argv[1]).read_bytes().decode("utf-8"))
    print(json.dumps(parser.rows, ensure_ascii=False))
