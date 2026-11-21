import base64
import hashlib
import inspect
import json
import marshal
import os
from pathlib import Path
import re
import shlex
import sqlite3
import sys

from calibre.constants import __version__
from calibre.db.cli import cmd_list
from calibre.srv import cdb
from calibre.utils.formatter import TemplateFormatter


def proof_path(value):
    if not re.fullmatch(r'/tmp/module-target-calibre-[a-z0-9_-]+', value):
        raise ValueError('Expected a controlled proof path')
    return Path(value)


def file_state(path):
    return {'exists': True, 'uid': path.stat().st_uid, 'base64': base64.b64encode(path.read_bytes()).decode()} if path.exists() else {'exists': False}


def make_template(command):
    return 'python:def evaluate(a, b):\n import subprocess\n return subprocess.check_output([\'sh\', \'-c\', ' + repr(command) + ']).decode(\'utf-8\')'


data = json.load(sys.stdin)
mode = sys.argv[-1]
if mode == 'verify':
    functions = {
        'calibre.db.cli.cmd_list.implementation': cmd_list.implementation,
        'calibre.srv.cdb.cdb_run': cdb.cdb_run,
        'calibre.utils.formatter.TemplateFormatter.safe_format': TemplateFormatter.safe_format,
        'calibre.utils.formatter.TemplateFormatter._eval_python_template': TemplateFormatter._eval_python_template,
    }
    hashes = {name: hashlib.sha256(marshal.dumps(inspect.unwrap(function).__code__)).hexdigest() for name, function in functions.items()}
    with sqlite3.connect('file:/home/app/library/metadata.db?mode=ro', uri=True) as database:
        books = [{'id': row[0], 'title': row[1]} for row in database.execute('SELECT id,title FROM books ORDER BY id')]
    result = {'version': __version__, 'uid': os.geteuid(), 'python': list(sys.version_info[:3]), 'source_sha256': hashes, 'books': books}
elif mode == 'command':
    path = proof_path(data['path'])
    content = base64.b64decode(data['content_base64'], validate=True).decode('utf-8')
    if data['kind'] == 'lf':
        command = 'printf First > ' + str(path) + '\nprintf Second >> ' + str(path)
    elif data['kind'] == 'double':
        command = 'printf %s "Double quoted spaces" > ' + str(path)
    elif data['kind'] == 'unicode':
        command = 'printf %s Calibre雪😀 > ' + str(path)
    else:
        command = 'printf %s ' + shlex.quote(content) + ' > ' + str(path)
    result = {'command_base64': base64.b64encode(command.encode()).decode(), 'content_base64': data['content_base64']}
elif mode == 'template':
    command = base64.b64decode(data['command_base64'], validate=True).decode('utf-8')
    if '/tmp/module-target-calibre-' not in command:
        raise ValueError('Expected a controlled native command')
    template = make_template(command)
    result = {'uid': os.geteuid(), 'template': template, 'arguments': [['template'], '', '', '', 1, template]}
elif mode == 'evaluate':
    from calibre.db.legacy import LibraryDatabase
    from calibre.ebooks.metadata.book.base import Metadata
    from calibre.ebooks.metadata.book.formatter import SafeFormat

    template = data['template']
    if '/tmp/module-target-calibre-' not in template:
        raise ValueError('Expected a controlled native template')
    database = LibraryDatabase('/home/app/library')
    try:
        books = sorted(database.new_api.all_book_ids())
        metadata = database.new_api.get_proxy_metadata(books[0]) if books else Metadata('Native formatter control')
        output = SafeFormat().safe_format(template, {}, 'TEMPLATE ERROR', metadata, global_vars={})
        result = {'uid': os.geteuid(), 'output': output, 'book_ids': books}
    finally:
        database.close()
elif mode in ['file', 'remove']:
    path = proof_path(data['path'])
    if mode == 'remove' and path.exists():
        path.unlink()
    result = file_state(path)
else:
    raise ValueError('Unsupported native operation')
print(json.dumps(result, ensure_ascii=True, sort_keys=True))
