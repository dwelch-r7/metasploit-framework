"""Actual Grafana process/API context; no startup or parser replacement."""
import json


class RuntimeContext:
    def capture_process_context(self):
        expected_home = self.assets['service_home']
        raw = self.command('sh', '-c',
                           "tr '\\000' '\\n' </proc/1/environ | sed -n '/^HOME=/p;/^GF_PATHS_/p'")
        values = dict(line.split('=', 1) for line in raw.splitlines())
        cwd = self.command('readlink', '/proc/1/cwd').strip()
        cli = self.command('sh', '-c', 'printf "HOME=%s\\nPWD=%s\\n" "$HOME" "$PWD"')
        cli_values = dict(line.split('=', 1) for line in cli.splitlines())
        self.pid_context = dict(filtered_environ=values, cwd=cwd, independent_cli=cli_values)
        assert values['HOME'] == expected_home and values['GF_PATHS_HOME'] == expected_home, values
        assert cli_values['HOME'] == values['HOME'] and cli_values['PWD'] == cwd, self.pid_context
        script = 'test ! -e "$HOME/.duckdbrc" && test ! -w "$HOME"'
        paths = [expected_home, expected_home + '/bin/grafana', '/run.sh']
        if self.mode != 'stock':
            script += (' && test ! -L "$HOME/.duckdb" && test -w "$HOME/.duckdb" && '
                       'test "$(stat -c %u "$HOME/.duckdb")" = 472')
            paths.append(expected_home + '/.duckdb')
        self.command('sh', '-c', script)
        self.pid_context['asset_and_cache_ownership'] = self.command('stat', '-c', '%u:%g %a %n', *paths)

    @staticmethod
    def rows(document):
        rows = []
        for frame in document.get('results', {}).get('A', {}).get('frames', []):
            names = [field['name'] for field in frame['schema']['fields']]
            values = frame['data']['values']
            rows.extend(dict(zip(names, row)) for row in zip(*values))
        return rows

    def observe_api_context(self, selected):
        expressions = {
            'version': 'SELECT version() AS engine_version',
            'home': "SELECT current_setting('home_directory') AS configured_home",
            'signature_policy': "SELECT current_setting('allow_unsigned_extensions') AS allowed",
            'platform': 'SELECT * FROM pragma_platform()',
            'extensions': "SELECT * FROM duckdb_extensions() WHERE extension_name='shellfs'"
        }
        self.api_context = {}
        for label, sql in expressions.items():
            status, document = self.sql([self.query('A', sql)], account=selected)
            self.api_context[label] = dict(expression=sql, status=status, response=document,
                                            rows=self.rows(document) if isinstance(document, dict) else [])

        version = self.api_context['version']
        assert version['status'] == 200 and self.value(version['response']) == self.assets['version'], version
        home = self.api_context['home']
        assert home['status'] == 200 and self.value(home['response']) in ('', self.assets['service_home']), home
        signature = self.api_context['signature_policy']
        assert signature['status'] == 200 and self.value(signature['response']) is False, signature
        # An empty home setting uses the process HOME; the observed installed
        # extension path below must independently identify that actual cache.
        extensions = self.api_context['extensions']
        assert extensions['status'] == 200 and len(extensions['rows']) == 1, extensions
        installed = extensions['rows'][0]
        expected_path = self.assets['service_home'] + '/.duckdb/extensions/v1.1.2/linux_amd64_gcc4/shellfs.duckdb_extension'
        assert installed['installed'] is True and installed['loaded'] is False, installed
        assert installed['install_path'] == expected_path, installed
        cli_extensions = json.loads(self.cli(
            "SELECT extension_name, installed, loaded, install_path FROM duckdb_extensions() WHERE extension_name='shellfs';"))
        assert len(cli_extensions) == 1 and all(
            cli_extensions[0][key] == installed[key]
            for key in ('extension_name', 'installed', 'loaded', 'install_path')), (cli_extensions, installed)
        self.api_context['cli_extensions'] = cli_extensions
        platform = self.api_context['platform']
        platform['supported'] = platform['status'] == 200 and bool(platform['rows'])
        if platform['supported']:
            assert self.value(platform['response']) in self.assets['cli_platform_candidates'], platform

