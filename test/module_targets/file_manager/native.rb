# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'nokogiri'
require 'uri'
require_relative 'profiles'

# Independent HTTP and physical-file observations against genuine plugin code.
class FileManagerNative
  GIF = Base64.strict_decode64('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==').freeze
  attr_reader :baseline

  def initialize(endpoint, profile, execute, record)
    @endpoint = endpoint
    @profile = profile
    @execute = execute
    @record = record
    @prefix = profile.fetch('prefix')
    @plugin = @prefix + '/wp-content/plugins/wp-file-manager'
    @connector = @plugin + '/lib/php/connector.minimal.php'
    @headers = { 'Host' => 'module-target.test' }
    @fields = {}
  end

  def snapshot(label, *)
    value = JSON.parse(@execute.call(*))
    @record.call('target-snapshots.jsonl', label: label, snapshot: value)
    value
  end

  def request(label, path, method: 'GET', body: nil, headers: {}, timeout: 20)
    raise ArgumentError, 'Native request requires a local path' unless path.start_with?('/')

    client = Net::HTTP.new(@endpoint.fetch('host'), @endpoint.fetch('port'), nil)
    client.open_timeout = 5
    client.read_timeout = timeout
    message = method == 'POST' ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    message['User-Agent'] = 'ModuleTargetNative/1.0'
    @headers.merge(headers).each { |key, value| message[key] = value }
    message.body = body if body
    response = client.request(message)
    @record.call('native-http.jsonl', label: label, method: method, path: path, request_body_base64: body && Base64.strict_encode64(body), request_headers: message.to_hash, code: response.code.to_i, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s))
    response
  end

  def api(label, fields, filename: nil, bytes: nil, mime: 'application/octet-stream')
    values = @fields.merge(fields)
    if filename
      boundary = '----ModuleTargetFileManagerNative7'
      body = values.map { |key, value| "--#{boundary}\r\nContent-Disposition: form-data; name=\"#{key}\"\r\n\r\n#{value}\r\n" }.join.b
      body << "--#{boundary}\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"#{filename}\"\r\nContent-Type: #{mime}\r\n\r\n".b << bytes.b << "\r\n--#{boundary}--\r\n".b
      content_type = 'multipart/form-data; boundary=' + boundary
    else
      body = URI.encode_www_form(values)
      content_type = 'application/x-www-form-urlencoded'
    end
    response = request(label, @connector, method: 'POST', body: body, headers: { 'Content-Type' => content_type })
    raise 'Native connector HTTP status differs' unless response.code == '200'

    JSON.parse(response.body)
  end

  def upload(label, name, bytes)
    result = api(label, { 'cmd' => 'upload', 'target' => @root_hash }, filename: name, bytes: bytes)
    raise 'Native upload was refused' unless result.fetch('added').map { |item| item.fetch('name') } == [name]

    verify_file(label + '-physical', name, bytes)
    name
  end

  def write(label, name, bytes)
    created = api(label + '-mkfile', { 'cmd' => 'mkfile', 'target' => @root_hash, 'name' => name })
    raise 'Native mkfile was refused' unless created.fetch('added').map { |item| item.fetch('name') } == [name]

    verify_file(label + '-empty', name, '')
    written = api(label + '-put', { 'cmd' => 'put', 'target' => created.fetch('added').first.fetch('hash'), 'content' => bytes })
    raise 'Native put was refused' unless written.fetch('changed').map { |item| item.fetch('name') } == [name]

    verify_file(label + '-physical', name, bytes)
    name
  end

  def path(name)
    @plugin + '/lib/files/' + name
  end

  def recover(names, label, owner: false)
    result = JSON.parse(@execute.call(owner ? 'cleanup-owned' : 'cleanup', names.join(',')))
    raise 'Native operator recovery differs' unless result.fetch('removed') == names

    @record.call('operator-recovery.jsonl', label: label, owner_payload: owner, files: names, result: result)
  end

  def verify_file(label, name, bytes)
    actual = snapshot(label).fetch('files').fetch(name)
    raise 'Native file bytes differ' unless actual.values_at('type', 'size', 'sha256') == ['file', bytes.bytesize, Digest::SHA256.hexdigest(bytes)]
  end

  def unrelated_health(label)
    response = request(label, '/')
    raise 'Unrelated HTTP service differs' unless response.code == '200' && response.body.include?('module-target-http-marker')

    digest = Digest::SHA256.hexdigest(response.body)
    raise 'Unrelated HTTP response changed' if @unrelated_sha256 && @unrelated_sha256 != digest

    @unrelated_sha256 = digest
    @record.call('unrelated-health.jsonl', label: label, code: 200, body_sha256: digest)
  end

  def controls
    return unrelated_health('native-unrelated-health') if @profile.fetch('mode') == 'unrelated'

    identity = snapshot('initial-identity')
    raise 'WordPress runtime identity differs' unless identity.values_at('core', 'php', 'uid') == ['5.2.4', '7.3.11', 33]

    mode = @profile.fetch('mode')
    if mode != 'absent'
      release = FileManagerProfiles::RELEASES.fetch(@profile.fetch('release'))
      raise 'Plugin identity differs' unless identity.values_at('plugin_version', 'active_plugins', 'installed_sha256', 'outer_sha256') == [@profile.fetch('release'), ['wp-file-manager/file_folder_manager.php'], release.fetch('installed_sha256'), release.fetch('sha256')]

      readme = request('native-plugin-readme', @plugin + '/readme.txt')
      raise 'Native plugin readme differs' unless readme.code == '200' && readme.body.include?('Stable tag: ' + @profile.fetch('release'))
    else
      raise 'Absent plugin unexpectedly installed' unless identity.fetch('plugin_version').nil? && identity.fetch('active_plugins').empty?
    end
    %w[/ /wp-login.php].each do |page|
      raise 'WordPress native page failed' unless request('native-wordpress-page', @prefix + page).code == '200'
    end
    if mode == 'fixed'
      fixed_controls
    elsif mode == 'absent'
      raise 'Absent connector exists' unless request('native-absent-connector', @connector).code == '404'

      login
    else
      affected_controls
    end
    @baseline = snapshot('native-baseline')
    raise 'Native operations changed plugin bytes or account password' unless @baseline.values_at('installed_sha256', 'account_hash') == identity.values_at('installed_sha256', 'account_hash')

    @record.call('native-controls.jsonl', mode: mode, status: 'passed', owning_calls: 0)
  end

  def affected_controls
    opened = api('native-root-open', { 'cmd' => 'open', 'init' => '1' })
    raise 'Native elFinder root is not writable' unless opened.fetch('cwd').fetch('write')

    @root_hash = opened.fetch('cwd').fetch('hash')
    raise 'Module root selector differs' unless api('native-module-root-alias', { 'cmd' => 'open', 'target' => 'l1_' }).fetch('cwd').fetch('hash') == @root_hash

    original = snapshot('native-before').fetch('files')
    { 'image.gif' => GIF, 'text.txt' => 'file-manager-native-café' }.each do |suffix, bytes|
      name = 'module-target-file-manager-' + suffix
      suffix == 'image.gif' ? upload('native-ordinary-image', name, bytes) : write('native-ordinary-text', name, bytes)
      response = request('native-ordinary-bytes', path(name))
      raise 'Native ordinary HTTP bytes differ' unless response.code == '200' && response.body.b == bytes.b

      recover([name], 'native-ordinary')
    end
    %w[upload mkfile-put].each do |method|
      name = 'module-target-file-manager-native-' + method + '.php'
      marker = 'file_manager_native_' + method.tr('-', '_')
      code = "<?php file_put_contents('/tmp/module-target-file-manager-native-proof','#{marker}');echo '#{marker}|' . posix_geteuid(); ?>"
      method == 'upload' ? upload('native-php-upload', name, code) : write('native-php-mkfile-put', name, code)
      response = request('native-php-execution', path(name))
      raise 'Native PHP execution or account differs' unless response.code == '200' && response.body == marker + '|33' && snapshot('native-php-proof').fetch('proof') == marker

      recover([name], 'native-php')
    end
    current = snapshot('native-after')
    original.each { |name, value| raise 'Original file changed' unless current.fetch('files').fetch(name) == value }
    raise 'Native proof remains' unless current.fetch('proof').nil?

    return unless @profile.fetch('mode') == 'readonly'

    @execute.call('harden')
    hardened = snapshot('native-hardened')
    raise 'Upload root remains writable' if hardened.fetch('files_writable')

    refused = api('native-denied-upload', { 'cmd' => 'upload', 'target' => @root_hash }, filename: 'module-target-file-manager-denied.gif', bytes: GIF, mime: 'image/gif')
    raise 'Native upload permission refusal differs' unless Array(refused['added']).empty? && refused.fetch('warning').include?('errPerm')

    refused = api('native-denied-mkfile', { 'cmd' => 'mkfile', 'target' => @root_hash, 'name' => 'module-target-file-manager-denied.php' })
    raise 'Native mkfile permission refusal absent' unless refused['error'] && Array(refused['added']).empty?
    raise 'Denied native operation changed state' unless snapshot('native-after-refusals') == hardened
  end

  def login
    response = request('native-admin-login-form', @prefix + '/wp-login.php')
    cookies = response.get_fields('set-cookie').to_a.map { |value| value.split(';').first }
    response = request('native-admin-login', @prefix + '/wp-login.php', method: 'POST', body: URI.encode_www_form('log' => 'module_admin', 'pwd' => 'module-target-password', 'testcookie' => '1'), headers: { 'Cookie' => cookies.join('; '), 'Content-Type' => 'application/x-www-form-urlencoded' })
    raise 'Native administrator authentication failed' unless response.code == '302'

    cookies.concat(response.get_fields('set-cookie').to_a.map { |value| value.split(';').first })
    raise 'Native administrator login cookie absent' unless cookies.any? { |value| value.start_with?('wordpress_logged_in_') }

    @headers['Cookie'] = cookies.join('; ')
    @headers['Origin'] = 'http://module-target.test'
    response = request('native-authenticated-dashboard', @prefix + '/wp-admin/')
    raise 'Authenticated dashboard failed' unless response.code == '200' && response.body.include?('module_admin')
  end

  def fixed_controls
    %w[GET POST].each do |method|
      response = request('native-fixed-removed-connector', @connector, method: method, body: method == 'POST' ? 'cmd=open&init=1' : nil)
      raise 'Fixed unsafe connector exists' unless response.code == '404'
    end
    login
    response = request('native-authenticated-file-manager', @prefix + '/wp-admin/admin.php?page=wp_file_manager')
    raise 'Fixed File Manager page failed' unless response.code == '200'

    line = Nokogiri::HTML(response.body).css('script').flat_map { |script| script.text.lines }.find { |text| text.start_with?('var fmfparams = ') }
    raise 'Authenticated File Manager metadata absent' unless line

    parameters = JSON.parse(line.delete_prefix('var fmfparams = ').sub(/;\s*\z/, ''))
    @connector = @prefix + '/wp-admin/admin-ajax.php'
    @fields = { 'action' => 'mk_file_folder_manager', '_wpnonce' => parameters.fetch('nonce') }
    opened = api('native-fixed-authenticated-open', { 'cmd' => 'open', 'init' => '1' })
    raise 'Fixed backend does not show actual WordPress files' unless opened.fetch('files').any? { |item| item['name'] == 'wp-admin' }

    directory = api('native-fixed-owned-directory', { 'cmd' => 'mkdir', 'target' => opened.fetch('cwd').fetch('hash'), 'name' => 'module-target-file-manager-native' }).fetch('added').first
    @root_hash = directory.fetch('hash')
    { 'image.gif' => GIF, 'text.txt' => 'file-manager-fixed-café' }.each do |name, bytes|
      if name == 'image.gif'
        result = api('native-fixed-image', { 'cmd' => 'upload', 'target' => @root_hash }, filename: name, bytes: bytes, mime: 'image/gif')
        raise 'Fixed ordinary image refused' unless result.fetch('added').first.fetch('name') == name
      else
        created = api('native-fixed-mkfile', { 'cmd' => 'mkfile', 'target' => @root_hash, 'name' => name }).fetch('added').first
        api('native-fixed-put', { 'cmd' => 'put', 'target' => created.fetch('hash'), 'content' => bytes })
      end
      physical = snapshot('native-fixed-physical', 'native', 'module-target-file-manager-native/' + name)
      raise 'Fixed ordinary physical bytes differ' unless physical.values_at('is_file', 'size', 'sha256', 'uid') == [true, bytes.bytesize, Digest::SHA256.hexdigest(bytes), 33]

      response = request('native-fixed-ordinary-bytes', @prefix + '/module-target-file-manager-native/' + name)
      raise 'Fixed ordinary HTTP bytes differ' unless response.code == '200' && response.body.b == bytes.b
    end
    removed = api('native-fixed-remove-directory', { 'cmd' => 'rm', 'targets[]' => @root_hash })
    raise 'Fixed backend recovery failed' unless removed.fetch('removed').include?(@root_hash) && snapshot('native-fixed-removed', 'native', 'module-target-file-manager-native').fetch('exists') == false

    @headers = { 'Host' => 'module-target.test' }
    @fields = {}
    @connector = @plugin + '/lib/php/connector.minimal.php'
  end
end
