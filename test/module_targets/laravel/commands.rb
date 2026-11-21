# frozen_string_literal: true

require 'net/http'
require 'shellwords'
require_relative '../rsync_creds/native'

# Shared command transport and physical proof checks for native Laravel targets.
module LaravelCommandTarget
  include RsyncCredentialTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), laravel_component + '-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def native_argv(mode)
    target_runtime.fetch('compose') + ['exec', '-T', 'target', 'php', '/opt/module-target-native.php', mode]
  end

  def native(mode, data, label)
    output, error, status = Open3.capture3(*native_argv(mode), stdin_data: JSON.generate(data))
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

  def native_php_command(command, path, content)
    expect(file(path)).to include('exists' => false)
    encoded = rc_json("begin;stock=framework.payloads.create('php/exec');stock.datastore['CMD']=#{command.inspect};Base64.strict_encode64(stock.generate.b);end")
    program = Base64.strict_decode64(encoded)
    (@rc[:native_payloads] ||= []) << { payload: 'php/exec', program_base64: encoded, command_base64: Base64.strict_encode64(command.b) }
    # Pass the stock program as one argv element to distinguish interpreter
    # readiness from an owner's shell quoting or transport failure.
    rc_command('native-php-exec', 'target', 'php', '-r', program)
    expect(file(path)).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
  ensure
    rc_command('remove-native-php-proof', 'target', 'rm', '-f', '--', path)
    expect(file(path)).to include('exists' => false)
    rc_save
  end

  def command_case(label, content, target: 1, payload: 'cmd/unix/generic', extra: {})
    2.times do |iteration|
      path = "/tmp/module-target-#{laravel_component}-owner-#{Process.pid}-#{label}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      native_command(command, path, content)
      native_php_command(command, path, content) if payload == 'php/exec'
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      # Datastore assignment preserves physical LF/CR bytes across the console.
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      options = { 'TARGET' => target, 'PAYLOAD' => payload, 'AutoCheck' => iteration.zero?, 'ForceExploit' => false, 'SSL' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 10 }.merge(extra)
      offset = rc_json("framework.instance_variable_get(:@#{laravel_component}_events).length")
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selected = rc_json('active_module.object_id')
      expect(selected).to eq(@selected_owner) if iteration.positive?
      @selected_owner = selected
      events = rc_json("framework.instance_variable_get(:@#{laravel_component}_events).drop(#{offset})")
      @rc[:calls] << { label: label, iteration: iteration, output: output, selection: selected, options: options, command_base64: Base64.strict_encode64(command.b), events: events }
      rc_save
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      actual = rc_poll(5) do
        value = file(path)
        value if value.fetch('exists')
      end
      expect(actual).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
      yield if block_given?
    ensure
      rc_command('remove-owner-proof', 'target', 'rm', '-f', '--', path)
      expect(file(path)).to include('exists' => false)
      rc_save
    end
  end
end
