# frozen_string_literal: true

require_relative '../laravel/commands'

# Native PHP classes and PHAR writer gate the real Ignition log transport.
module IgnitionTarget
  include LaravelCommandTarget

  LOGFILE = '/var/www/storage/logs/laravel.log'

  def laravel_component
    'ignition'
  end

  def laravel_owner
    IgnitionObservation::OWNER
  end

  def laravel_uid
    33
  end

  def native_argv(mode)
    command = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'target', 'php']
    command += ['-d', 'phar.readonly=0'] if mode == 'gadget'
    command + ['/opt/module-target-native.php', mode]
  end

  def native_verify(label)
    data = native('verify', {}, label)
    vendor = JSON.parse(File.read('test/module_targets/ignition/vendor.json'))
    expect(data).to include('php' => vendor.fetch('php'), 'laravel' => vendor.fetch('laravel'), 'uid' => laravel_uid, 'debug' => ENV.fetch('IGNITION_DEBUG_EXPECTED', 'true') == 'true', 'environment' => 'local', 'phar_readonly' => '1', 'log' => LOGFILE)
    expect(data.fetch('source_sha256')).to eq(vendor.fetch('source_sha256'))
    data
  end

  def solution(label, view)
    endpoint = target_endpoint('target')
    uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: '/_ignition/execute-solution')
    client = Net::HTTP.new(uri.hostname, uri.port, nil)
    client.open_timeout = 5
    client.read_timeout = 10
    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/json'
    request.body = JSON.generate(solution: 'Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution', parameters: { viewFile: view, variableName: 'nativeVariable' })
    response = client.start { |connection| connection.request(request) }
    # Debug pages are large; retain each body once instead of rewriting them in
    # every intermediate receipt snapshot.
    artifact = format('ignition-native-http-%04d.body', @rc.fetch(:http).length)
    File.binwrite(File.join(target_runtime.fetch('artifacts'), artifact), response.body.to_s.b)
    @rc[:http] << { label: label, path: uri.path, view: view, code: response.code.to_i, body_artifact: artifact, body_sha256: Digest::SHA256.hexdigest(response.body.to_s.b) }
    rc_save
    response
  end

  def native_clear_log(label)
    expect(solution(label, 'php://filter/read=consumed/resource=' + LOGFILE).code).to eq('200')
    expect(native('log', {}, label + '-state')).to include('exists' => true, 'size' => 0, 'uid' => laravel_uid)
  end

  def owner_cleanup
    # This is a read-only oracle: the next native control must not repair an
    # owner's cleanup before the repeated execution is assessed.
    rc_poll(5) do
      state = native('log', {}, 'owner-cleanup-state')
      expect(state).to include('exists' => true, 'uid' => laravel_uid)
      state.fetch('size').zero?
    end
  end

  def native_command(command, path, content)
    archive = path + '-source.phar'
    expect(file(path)).to include('exists' => false)
    generated = native('gadget', { archive: archive, command_base64: Base64.strict_encode64(command.b) }, 'native-gadget')
    expect(generated.fetch('uid')).to eq(laravel_uid)
    expect(file(path)).to include('exists' => false)
    native_clear_log('clear-before-native')
    solution('native-encoded', generated.fetch('transport'))
    solution('native-alignment', 'AA')
    solution('native-convert', 'php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=' + LOGFILE)
    converted = native('log', {}, 'native-converted')
    expect(converted.fetch('base64')).to eq(generated.fetch('phar_base64'))
    expect(file(path)).to include('exists' => false)
    solution('native-trigger', 'phar://' + LOGFILE + '/proof.txt')
    expect(file(path)).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
  ensure
    primary = $ERROR_INFO
    begin
      [path, archive].compact.each { |name| native('remove', { path: name }, 'remove-native-proof') }
      expect(file(path)).to include('exists' => false) if path
      native_clear_log('clear-after-native')
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end
end
