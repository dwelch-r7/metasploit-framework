# frozen_string_literal: true

require_relative '../calibre/acceptance'

# The identical template works locally, then reaches genuine remote suppression.
module CalibreFixedTarget
  include CalibreTarget

  def native_verify(label)
    value = native('verify', {}, label)
    expect(value).to eq(JSON.parse(File.read('test/module_targets/calibre_fixed/installed-7.16.0.json')))
    value
  end

  def fixed_control(command, path, content)
    marker = 'calibre-fixed-' + @rc.fetch(:controls).length.to_s
    expect(file(path)).to include('exists' => false)
    generated = native('template', { command_base64: Base64.strict_encode64(('echo ' + marker + '; ' + command).b) }, 'fixed-template')
    expect(file(path)).to include('exists' => false)
    local = native('evaluate', { template: generated.fetch('template') }, 'fixed-local-positive')
    positive = file(path)
    expect(positive).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
    expect(local.fetch('output')).to eq(marker + "\n")
    native('remove', { path: path }, 'remove-fixed-local')
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
    denied = file(path)
    @rc[:controls] << { marker: marker, path: path, command_base64: Base64.strict_encode64(command.b), content_base64: Base64.strict_encode64(content.b), arguments: generated.fetch('arguments'), local: local, positive: positive, http_code: response.code.to_i, response_base64: Base64.strict_encode64(response.body.b), denied: denied }
    rc_save
    expect(response.code).to eq('200')
    # Captured from the native 7.16.0 pilot, with the same real book and template.
    expect(JSON.parse(response.body).fetch('result')).to include('book_ids' => [1], 'data' => { 'template' => 'Template not allowed' })
    expect(denied).to include('exists' => false)
  ensure
    primary = $ERROR_INFO
    begin
      native('remove', { path: path }, 'remove-fixed-control') if path
      expect(file(path)).to include('exists' => false) if path
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def fixed_owner
    content = "Fixed 'single' \"double\" $HOME 雪😀\r\nNext\n"
    2.times do |iteration|
      path = "/tmp/module-target-calibre-fixed-owner-#{Process.pid}-#{iteration}"
      generated = native('command', { kind: 'crlf-quotes', content_base64: Base64.strict_encode64(content.b), path: path }, 'fixed-command')
      command = Base64.strict_decode64(generated.fetch('command_base64'))
      fixed_control(command, path, content)
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=Base64.strict_decode64(#{generated.fetch('command_base64').inspect});true;end")
      options = { 'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic', 'AutoCheck' => true, 'ForceExploit' => false, 'SSL' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
      offset = rc_json('framework.instance_variable_get(:@calibre_events).length')
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_fixed_owner) if iteration.positive?
      @selected_fixed_owner = selection
      events = rc_json("framework.instance_variable_get(:@calibre_events).drop(#{offset})")
      proof = file(path)
      @rc[:calls] << { kind: 'fixed-owner', iteration: iteration, options: options, command_base64: generated.fetch('command_base64'), output: output, selection: selection, events: events, denied: proof }
      rc_save
      expect(events.filter_map { |event| event['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'Calibre version 7.16.0 is not vulnerable' }])
      expect(events.select { |event| event['event'] == 'call' && event['method'] == 'exec_calibre' }).to eq([])
      expect(events.select { |event| event.key?('request') }).to eq([])
      expect(output).to include('Calibre version 7.16.0 is not vulnerable')
      expect(proof).to include('exists' => false)
    ensure
      native('remove', { path: path }, 'remove-fixed-owner') if path
      expect(file(path)).to include('exists' => false) if path
      rc_save
    end
  end
end
