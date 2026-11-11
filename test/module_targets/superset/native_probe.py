"""Genuine installed-application controls, before any Framework invocation."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import traceback

from native_http import NativeHTTP


def main():
    runtime = json.loads(Path(sys.argv[1]).read_text())
    native = NativeHTTP(runtime['compose'], runtime['origin'], runtime['artifacts'])
    result = {'status': 'native_failed', 'framework_calls': 0}
    try:
        identity = native.app('identity')
        result['identity'] = identity
        assert identity['packages']['apache-superset'] == runtime.get('version', '2.0.0'), identity
        assert identity['uid'] == identity['metadata_stat']['uid'] == 1000, identity
        assert identity['configuration']['SQLALCHEMY_DATABASE_URI'] == 'sqlite:////app/superset_home/superset.db'
        assert identity['configuration']['SECRET_KEY'] == 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET'
        for name, expected in runtime['source_sha256'].items():
            observed = identity['source_files'][name]
            assert observed['sha256'] == expected, (name, observed['sha256'], expected)
            assert hashlib.sha256(base64.b64decode(observed['bytes_base64'])).hexdigest() == expected
        result['seed'] = native.app(
            'seed', datasource_uri='postgresql://module_native:module-target-superset-database-password@reporting_db:5432/module_native')
        result['cookie_controls'] = native.cookie_controls()
        result['status'] = 'native_passed'
    except BaseException as error:
        result['failure'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        raise
    finally:
        native.save()
        Path(runtime['artifacts'], 'native-result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
