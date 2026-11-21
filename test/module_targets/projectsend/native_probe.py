"""Independent publisher installation, PHP execution and option-state controls."""

from pathlib import Path
import base64
import datetime
import hashlib
import html.parser
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


class Inputs(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs = {}
        self.title = ''
        self.in_title = False

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == 'title':
            self.in_title = True
        if tag == 'input' and attributes.get('name'):
            self.inputs[attributes['name']] = attributes.get('value', '')

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


class Native:
    def __init__(self, runtime, directory):
        self.runtime = runtime
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.journal = dict(commands=[], http=[])
        self.jar = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())
        endpoint = runtime['endpoints']['target']
        self.base = 'http://' + endpoint['host'] + ':' + str(endpoint['port']) + '/'

    def save(self):
        (self.directory / 'journal.json').write_text(json.dumps(self.journal, indent=2) + '\n')

    def command(self, label, *arguments, data=None, user=None):
        argv = self.runtime['compose'] + ['exec', '-T'] + ([] if user is None else ['--user', str(user)]) + ['target', *arguments]
        result = subprocess.run(argv, input=data, capture_output=True, timeout=45)
        self.journal['commands'].append(dict(label=label, argv=argv, exit=result.returncode, stdout_base64=base64.b64encode(result.stdout).decode(), stderr=result.stderr.decode(errors='replace')))
        self.save()
        assert result.returncode == 0, self.journal['commands'][-1]
        return result.stdout

    def observe(self, mode, data=None):
        output = self.command(mode, 'php83', '/opt/module-target-projectsend-observe.php', mode, data=None if data is None else json.dumps(data).encode(), user=1000)
        return json.loads(output)

    def request(self, method, path, data=None):
        encoded = None if data is None else urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(urllib.parse.urljoin(self.base, path), data=encoded, method=method)
        try:
            response = self.client.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            result = dict(status=response.status, headers=dict(response.headers), body_base64=base64.b64encode(raw).decode())
        self.journal['http'].append(dict(method=method, path=path, data=data, response=result))
        self.save()
        return result

    def file(self, path, remove=False):
        assert re.fullmatch(r'(?:/tmp/|/app/www/public/upload/files/)module-target-projectsend-[a-z0-9_.-]+', path), path
        code = '$p=$argv[1];if($argv[2]==="1"&&file_exists($p)){if(!unlink($p)){throw new RuntimeException("Cannot remove proof");}}echo json_encode(file_exists($p)?["exists"=>true,"uid"=>fileowner($p),"base64"=>base64_encode(file_get_contents($p))]:["exists"=>false],JSON_THROW_ON_ERROR);'
        return json.loads(self.command('remove-proof' if remove else 'file-proof', 'php83', '-r', code, path, '1' if remove else '0', user=1000))

    def web_control(self):
        path = '/tmp/module-target-projectsend-native-' + str(os.getpid())
        web = '/app/www/public/upload/files/module-target-projectsend-native-' + str(os.getpid()) + '.php'
        marker = "Native 'quoted' & Unicode 雪\r\n".encode()
        assert self.file(path) == self.file(web) == dict(exists=False)
        program = '<?php $marker=base64_decode("' + base64.b64encode(marker).decode() + '");unlink(__FILE__);file_put_contents("' + path + '",$marker);echo json_encode(["uid"=>fileowner("' + path + '"),"marker"=>$marker],JSON_THROW_ON_ERROR);'
        try:
            self.command('native-php-write', 'php83', '-r', 'if(file_put_contents($argv[1],base64_decode($argv[2],true))===false){throw new RuntimeException("Cannot create native web control");}', web, base64.b64encode(program.encode()).decode(), user=1000)
            response = self.request('GET', 'upload/files/' + Path(web).name)
            assert response['status'] == 200, response
            assert json.loads(base64.b64decode(response['body_base64'])) == dict(uid=1000, marker=marker.decode())
            assert self.file(path) == dict(exists=True, uid=1000, base64=base64.b64encode(marker).decode())
            assert self.file(web) == dict(exists=False)
            return dict(passed=True, response=response, proof=self.file(path))
        finally:
            assert self.file(web, remove=True) == self.file(path, remove=True) == dict(exists=False)

    def csrf(self):
        response = self.request('GET', 'index.php')
        assert response['status'] == 200, response
        parser = Inputs()
        parser.feed(base64.b64decode(response['body_base64']).decode())
        token = parser.inputs.get('csrf_token')
        assert token and re.fullmatch('[a-f0-9]{64}', token)
        return token

    def index_title(self):
        response = self.request('GET', 'index.php')
        assert response['status'] == 200
        parser = Inputs()
        parser.feed(base64.b64decode(response['body_base64']).decode())
        assert '»' in parser.title
        return parser.title.split('»', 1)[1].strip()

    def post_mutation_status(self, response):
        if response['status'] == 303:
            return dict(status=303)
        assert response['status'] == 500, response
        code = '$out=[];$files=new RecursiveIteratorIterator(new RecursiveDirectoryIterator("/config/log",FilesystemIterator::SKIP_DOTS));foreach($files as $file){if($file->isFile()){$out[$file->getPathname()]=base64_encode(substr(file_get_contents($file->getPathname()),-65536));}}echo json_encode($out,JSON_THROW_ON_ERROR);'
        logs = json.loads(self.command('post-mutation-server-errors', 'php83', '-r', code))
        return dict(status=500, post_mutation_error='Cause requires separate diagnostic; exact SQL and HTML mutation/recovery are still mandatory', logs=logs)

    def title_control(self, baseline):
        token = self.csrf()
        title = next(row['value'] for row in baseline if row['name'] == 'this_install_title')
        try:
            response = self.request('POST', 'options.php?section=branding', dict(csrf_token=token, this_install_title='Native control title'))
            status = self.post_mutation_status(response)
            changed = self.observe('options')
            expected = [dict(row, value='Native control title') if row['name'] == 'this_install_title' else row for row in baseline]
            assert changed == expected
            assert self.index_title() == 'Native control title'
            response = self.request('POST', 'options.php?section=branding', dict(csrf_token=token, this_install_title=title))
            self.post_mutation_status(response)
            assert self.observe('options') == baseline
            assert self.index_title() == title
            return dict(passed=True, exact_title_restored=True, all_options_preserved=True, post_mutation=status)
        finally:
            if self.observe('options') != baseline:
                self.observe('restore-options', baseline)

    def install(self):
        configuration = "<?php\ndefine('DB_DRIVER','mysql');define('DB_HOST','database');define('DB_NAME','projectsend');define('DB_USER','projectsend');define('DB_PASSWORD','module-target-projectsend-password');define('TABLES_PREFIX','mcv_');define('SITE_LANG','en');define('MAX_FILESIZE',16);define('EMAIL_ENCODING','utf-8');define('DEBUG',false);\n"
        self.command('configure-database', 'php83', '-r', '$p="/config/projectsend/sys.config.php";if(file_exists($p)){throw new RuntimeException("Configuration already exists");}if(file_put_contents($p,base64_decode($argv[1],true))===false){throw new RuntimeException("Cannot create configuration");}chmod($p,0600);chown($p,1000);chgrp($p,1000);', base64.b64encode(configuration.encode()).decode())
        response = self.request('GET', 'install/index.php')
        assert response['status'] == 200, response
        parser = Inputs()
        parser.feed(base64.b64decode(response['body_base64']).decode())
        assert 'admin_username' in parser.inputs
        data = dict(install_title='ProjectSend native fixture', base_uri=self.base, admin_name='Module Target Admin', admin_username='moduleadmin', admin_email='moduleadmin@example.test', admin_pass='Native-ProjectSend-42!')
        response = self.request('POST', 'install/index.php', data)
        assert response['status'] == 303 and response['headers'].get('Location') == 'install-success.php', response
        assert self.request('GET', 'index.php')['status'] == 200
        configuration_sha256 = hashlib.sha256(configuration.encode()).hexdigest()
        assert self.command('configuration-fingerprint', 'sha256sum', '/config/projectsend/sys.config.php').decode().split()[0] == configuration_sha256
        return dict(installed=True, admin='moduleadmin', configuration_sha256=configuration_sha256)


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    action, *arguments = sys.argv[1:]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f').lower()
    native = Native(runtime, Path(runtime['artifacts']) / ('projectsend-native-' + action + '-' + stamp))
    state_path = Path(runtime['artifacts']) / 'projectsend-state.json'
    vendor = json.loads(Path('test/module_targets/projectsend/vendor.json').read_text())
    try:
        if action == 'before':
            metadata = native.observe('metadata')
            assert metadata['uid'] == 1000 and metadata['files_sha256'] == vendor['files_sha256']
            installed = native.install()
            factory = native.observe('options')
            state = dict(metadata=metadata, factory=factory, configuration_sha256=installed['configuration_sha256'])
            state_path.write_text(json.dumps(state, indent=2) + '\n')
            seed = dict(this_install_title='ProjectSend & native 雪', footer_custom_enable='1', footer_custom_content='<span>Native fixture footer</span>', use_browser_lang='1', files_descriptions_use_ckeditor='1', clients_can_upload='1', clients_can_delete_own_files='1', clients_can_set_expiration_date='1', expired_files_hide='0')
            native.observe('set-options', seed)
            baseline = native.observe('options')
            values = {row['name']: row['value'] for row in baseline}
            assert all(values[name] == value for name, value in seed.items())
            state['baseline'] = baseline
            state_path.write_text(json.dumps(state, indent=2) + '\n')
            result = dict(passed=True, module_invoked=False, version=vendor['version'], installed=installed, **state, web=native.web_control(), title=native.title_control(baseline))
        elif action == 'snapshot':
            result = native.observe('options')
        elif action == 'restore-baseline':
            state = json.loads(state_path.read_text())
            native.observe('restore-options', state['baseline'])
            assert native.observe('options') == state['baseline']
            result = dict(restored=True)
        elif action == 'after':
            state = json.loads(state_path.read_text())
            preserved = native.observe('options') == state.get('baseline')
            native.observe('restore-options', state['factory'])
            restored = native.observe('options') == state['factory']
            metadata = native.observe('metadata')
            assert metadata == state['metadata']
            assert native.command('configuration-fingerprint', 'sha256sum', '/config/projectsend/sys.config.php').decode().split()[0] == state['configuration_sha256']
            result = dict(preserved=preserved, restored=restored, metadata=metadata)
        else:
            raise ValueError('Unsupported native action')
        native.journal['result'] = result
        print(json.dumps(result))
    except Exception as error:
        native.journal['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        native.save()


if __name__ == '__main__':
    main()
