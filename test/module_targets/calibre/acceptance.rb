# frozen_string_literal: true

require 'English'
require_relative '../laravel/commands'

# Reuse command/resource/console transport; Calibre supplies its own CLI and API.
module CalibreTarget
  include LaravelCommandTarget

  CASES = {
    'ascii' => 'calibre-command-ascii',
    'single' => 'Single quoted spaces',
    'double' => 'Double quoted spaces',
    'unicode' => 'Calibre雪😀',
    'lf' => 'FirstSecond',
    'crlf-quotes' => "Calibre 'single' \"double\" $HOME ${literal} $(printf nested) 雪😀\r\nEnd\n"
  }.freeze

  def laravel_component
    'calibre'
  end

  def laravel_owner
    CalibreObservation::OWNER
  end

  def laravel_uid
    1000
  end

  def native_argv(mode)
    target_runtime.fetch('compose') + ['exec', '-T', '--user', 'app', 'target', 'calibre-debug', '-e', '/opt/module-target-native.py', '--', mode]
  end

  def native_verify(label)
    value = native('verify', {}, label)
    expect(value).to eq(JSON.parse(File.read('test/module_targets/calibre/installed-7.14.0.json')))
    value
  end

  def file(path)
    native('file', { path: path }, 'proof-file')
  end

  def native_control(command, path, content)
    marker = 'calibre-native-' + @rc.fetch(:controls).length.to_s
    expect(file(path)).to include('exists' => false)
    generated = native('template', { command_base64: Base64.strict_encode64(('echo ' + marker + '; ' + command).b) }, 'native-template')
    expect(file(path)).to include('exists' => false)
    local = native('evaluate', { template: generated.fetch('template') }, 'native-local')
    expect(file(path)).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
    expect(local.fetch('output')).to include(marker)
    native('remove', { path: path }, 'remove-local-proof')
    expect(file(path)).to include('exists' => false)
    endpoint = target_endpoint('target')
    client = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    client.open_timeout = 5
    client.read_timeout = 15
    response = client.start do |connection|
      request = Net::HTTP::Post.new('/cdb/cmd/list')
      request['Content-Type'] = 'application/json'
      request.body = JSON.generate(generated.fetch('arguments'))
      connection.request(request)
    end
    proof = file(path)
    @rc[:controls] << { marker: marker, command_base64: Base64.strict_encode64(command.b), content_base64: Base64.strict_encode64(content.b), path: path, local: local, http_code: response.code.to_i, response_base64: Base64.strict_encode64(response.body.b), proof: proof }
    rc_save
    expect(response.code).to eq('200')
    expect(JSON.parse(response.body).fetch('result').fetch('data').fetch('template').values).to eq([marker + "\n"])
    expect(proof).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
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

  def owner_command_case(kind, content)
    2.times do |iteration|
      path = "/tmp/module-target-calibre-owner-#{Process.pid}-#{kind}-#{iteration}"
      generated = native('command', { kind: kind, content_base64: Base64.strict_encode64(content.b), path: path }, 'command-factory')
      command = Base64.strict_decode64(generated.fetch('command_base64'))
      native_control(command, path, content)
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=Base64.strict_decode64(#{generated.fetch('command_base64').inspect});true;end")
      options = { 'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic', 'AutoCheck' => iteration.zero?, 'ForceExploit' => false, 'SSL' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 15 }
      offset = rc_json('framework.instance_variable_get(:@calibre_events).length')
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_owner) if iteration.positive?
      @selected_owner = selection
      events = rc_json("framework.instance_variable_get(:@calibre_events).drop(#{offset})")
      proof = file(path)
      @rc[:calls] << { kind: kind, iteration: iteration, options: options, output: output, selection: selection, command_base64: generated.fetch('command_base64'), events: events, proof: proof }
      rc_save
      expect(events.select { |event| event['event'] == 'call' && event['method'] == 'exec_calibre' }.length).to eq(1)
      expect(proof).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
    ensure
      native('remove', { path: path }, 'remove-owner-proof') if path
      expect(file(path)).to include('exists' => false) if path
      rc_save
    end
  end
end
