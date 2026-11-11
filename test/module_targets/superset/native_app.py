"""Use installed Superset/Flask APIs inside the disposable target, without Framework."""
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def state(database, security):
    from superset.models.core import Database
    from superset.models.dashboard import Dashboard
    from sqlalchemy import text

    return {
        'users': [{'id': user.id, 'username': user.username, 'password': user.password,
                   'roles': sorted(role.name for role in user.roles)}
                  for user in database.session.query(security.user_model).order_by(security.user_model.id)],
        'databases': [{'id': item.id, 'name': item.database_name, 'uri': item.sqlalchemy_uri,
                       'decrypted_uri': item.sqlalchemy_uri_decrypted, 'parameters': item.parameters}
                      for item in database.session.query(Database).order_by(Database.id)],
        'dashboards': [{'id': item.id, 'title': item.dashboard_title}
                       for item in database.session.query(Dashboard).order_by(Dashboard.id)],
        'key_values': [{key: {'bytes_base64': base64.b64encode(value).decode()} if isinstance(value, bytes) else value
                        for key, value in dict(row).items()}
                       for row in database.session.execute(text('SELECT * FROM key_value ORDER BY id'))],
    }


def main():
    from superset.extensions import appbuilder, db
    from superset.app import create_app

    options = json.loads(sys.argv[1])
    app = create_app()
    with app.app_context():
        security = appbuilder.sm
        action = options['action']
        serializer = app.session_interface.get_signing_serializer(app)
        assert serializer is not None
        if action == 'identity':
            import superset

            root = Path(superset.__file__).parent
            files = {}
            for relative in ['config.py', 'constants.py', 'initialization/__init__.py', 'models/core.py',
                             'key_value/commands/get.py', 'key_value/models.py']:
                path = root / relative
                files[relative] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                   'bytes_base64': base64.b64encode(path.read_bytes()).decode()}
            result = {'uid': os.getuid(), 'gid': os.getgid(), 'cwd': os.getcwd(), 'source_files': files,
                      'packages': {name: importlib.metadata.version(name) for name in
                                   ['apache-superset', 'Flask', 'Flask-Login', 'Flask-AppBuilder', 'itsdangerous', 'SQLAlchemy', 'Werkzeug']},
                      'configuration': {name: app.config.get(name) for name in
                                        ['SECRET_KEY', 'SQLALCHEMY_DATABASE_URI', 'SESSION_COOKIE_NAME', 'WTF_CSRF_ENABLED']},
                      'metadata_stat': {'uid': Path('/app/superset_home/superset.db').stat().st_uid,
                                        'gid': Path('/app/superset_home/superset.db').stat().st_gid}}
        elif action == 'seed':
            from superset.models.core import Database

            assert security.find_user(username='lab-user') is None, 'Native seed must start fresh'
            assert db.session.query(Database).count() == 0, 'Unexpected pre-existing datasource'
            role = security.find_role('Gamma')
            assert role is not None
            user = security.add_user('lab-user', 'Module', 'User', 'user@module-target.test', role,
                                     password='module-target-superset-user-password')
            assert user is not None
            datasource = Database(database_name='Module Native PostgreSQL', expose_in_sqllab=True)
            datasource.set_sqlalchemy_uri(options['datasource_uri'])
            db.session.add(datasource)
            db.session.commit()
            assert datasource.password == 'module-target-superset-database-password'
            result = state(db, security)
        elif action == 'decode':
            result = {'decoded': serializer.loads(options['cookie'])}
        elif action == 'sign':
            # This is the application's actual session serializer and data type.
            result = {'cookie': serializer.dumps(options['content'])}
        elif action == 'state':
            result = state(db, security)
        else:
            raise ValueError('Unknown native operation: ' + action)
    # Superset logs initialization messages separately; an anchored line binds JSON.
    print('MODULE-TARGET-SUPERSET-JSON:' + json.dumps(result, default=str))


if __name__ == '__main__':
    main()
