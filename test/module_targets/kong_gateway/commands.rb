# frozen_string_literal: true

require 'English'
require 'shellwords'
require_relative '../rsync_creds/native'

# Compare native target state with the actual console owner and its cleanup.
module KongGatewayTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/http/kong_gateway_admin_api_rce'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'kong.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[app database]
  end

  def kg_native(operation, *arguments)
    argv = ['python3', 'test/module_targets/kong_gateway/native.py', ENV.fetch('MODULE_TARGET_RUNTIME'), operation, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    line = output.lines.grep(/^KONG_NATIVE=/).last
    expect(line).not_to be_nil, output
    value = JSON.parse(line.delete_prefix('KONG_NATIVE='))
    expect(value.fetch('passed')).to be(true)
    value.fetch('result')
  end

  def kg_events
    rc_json('framework.instance_variable_get(:@kong_gateway_events)')
  end

  def kg_proxy(public_host: false)
    expect(console_command("set PUBLIC-API-RPORT #{@rc.fetch(:proxy_port)}")).not_to include('[-]')
    expect(console_command('set PUBLIC-API-RHOST 127.0.0.1')).not_to include('[-]') if public_host
    expect(console_command('unset PUBLIC-API-RHOST')).not_to include('[-]') unless public_host
    actual = rc_json("[active_module.datastore['PUBLIC-API-RPORT'],active_module.datastore['PUBLIC-API-RHOST']]")
    expect(actual).to eq([@rc.fetch(:proxy_port), public_host ? '127.0.0.1' : nil])
  end

  def kg_command(label, contents, reuse: false, public_host: false)
    path = "/tmp/module-target-kong-owner-#{Process.pid}-#{label}"
    expect(kg_native('file', path)).to eq('exists' => false)
    command = block_given? ? yield(path) : "printf %s #{Shellwords.escape(contents)} > #{path}"
    kg_native('command', command, path, Base64.strict_encode64(contents.b))
    unless reuse
      console_command('back')
      expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command|No results/)
    end
    expect(console_command('set PAYLOAD cmd/unix/generic')).not_to match(/Failed|Invalid|not found/)
    kg_proxy(public_host: public_host)
    expect(rc_json("begin;active_module.datastore['CMD']=#{command.inspect};active_module.datastore['CMD'];end")).to eq(command)
    options = { 'PAYLOAD' => 'cmd/unix/generic', 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
    offset = kg_events.length
    call = { label: label, command_base64: Base64.strict_encode64(command.b), path: path, enabled: ENV.fetch('KONG_EXPECT_PLUGIN') == 'true' }
    @rc[:calls] << call
    call[:output] = run_target_module(OWNER, 'app', options, action: 'run -z', reuse_module: true, allow_errors: true, command_timeout: 100)
    call[:events] = kg_events.drop(offset)
    call[:selection] = rc_json('active_module.object_id')
    call[:datastore_after_base64] = rc_json('Base64.strict_encode64(active_module.datastore["CMD"].b)')
    call[:file] = kg_native('file', path)
    invocations = call[:events].select { |event| event['event'] == 'call' && event['method'] == 'exploit' }
    expect(invocations.map { |event| event.fetch('datastore_command_base64') }).to eq([call.fetch(:command_base64)])
    checks = call[:events].select { |event| event['event'] == 'return' && event['method'] == 'check' }
    expect(checks.map { |event| event.fetch('check').fetch('code') }).to eq([call.fetch(:enabled) ? 'appears' : 'safe'])
    expect(call[:selection]).to eq(@rc.fetch(:previous_selection)) if reuse
    @rc[:previous_selection] = call[:selection]
    expect(call.fetch(:datastore_after_base64)).to eq(call.fetch(:command_base64))
    actual = call.fetch(:file)
    if call.fetch(:enabled)
      expect(call.fetch(:output)).not_to include('[-]')
      expect(actual).to eq('exists' => true, 'uid' => @rc.fetch(:identity).fetch('uid'), 'base64' => Base64.strict_encode64(contents.b))
      deliveries = call[:events].select { |event| event['event'] == 'return' && event['method'] == 'create_plugin' }
      expect(deliveries.map { |event| event.fetch('payload_base64') }).to eq([call.fetch(:command_base64)])
    else
      expect(call.fetch(:output)).to include('not-vulnerable')
      expect(actual).to eq('exists' => false)
      mutations = call[:events].select { |event| event['event'] == 'call' && %w[create_route create_plugin request_route].include?(event['method']) }
      expect(mutations).to be_empty
    end
  ensure
    primary_error = $ERROR_INFO
    call[:error] = primary_error.message if call && primary_error
    begin
      if path
        rc_command('remove-owner-proof', 'app', 'rm', '-f', path)
        expect(kg_native('file', path)).to eq('exists' => false)
      end
      kg_native('audit') if @rc && @rc[:identity]
      call[:cleanup_verified] = true if call
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc[:cleanup_errors] << { label: label, type: e.class.name, message: e.message, primary_error: primary_error&.message }
      raise unless primary_error
    ensure
      rc_save
    end
  end
end
