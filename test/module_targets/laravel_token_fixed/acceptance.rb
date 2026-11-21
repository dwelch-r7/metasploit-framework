# frozen_string_literal: true

require_relative '../laravel_token/acceptance'

# Local deserialization proves gadget readiness before fixed HTTP denial.
module LaravelTokenFixedTarget
  include LaravelTokenTarget

  def laravel_vendor_file
    'test/module_targets/laravel_token/releases/5.6.30/vendor.json'
  end

  def fixed_control(method, command, path, content)
    echo = "fixed-#{method}-#{@rc.fetch(:controls).length}"
    controlled = 'echo ' + echo + '; ' + command
    expect(file(path)).to include('exists' => false)
    generated = native('gadget', { method: method, command_base64: Base64.strict_encode64(controlled.b) }, 'fixed-gadget')
    expect(file(path)).to include('exists' => false)
    evaluated = native('evaluate', { token: generated.fetch('token'), path: path }, 'local-default-decrypt')
    expect(evaluated).to include('uid' => laravel_uid, 'decoded_class' => 'Illuminate\\Broadcasting\\PendingBroadcast', 'token_sha256' => Digest::SHA256.hexdigest(generated.fetch('token')))
    expect(Base64.strict_decode64(evaluated.fetch('output_base64')).lines.map(&:strip)).to include(echo)
    positive = file(path)
    expect(positive).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
    native('remove', { path: path }, 'remove-local-positive')
    expect(file(path)).to include('exists' => false)
    response = post_token('same-token-fixed-' + method.to_s, generated.fetch('token'))
    denied = file(path)
    @rc[:controls] << { method: method, echo: echo, token_sha256: evaluated.fetch('token_sha256'), evaluation: evaluated, positive_proof: positive, content_base64: Base64.strict_encode64(content.b), http_code: response.code.to_i, denied: denied }
    rc_save
    # Derived from the genuine 5.6.30 native capture, not a synthetic endpoint.
    expect(response.code).to eq('419')
    expect(response.body).to include('Page Expired')
    expect(response.body.b.lines.map(&:strip)).not_to include(echo)
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

  def fixed_owner_commands
    content = "Fixed 'quote' \"double\" \\ $HOME 雪😀\r\nNext\tend\n"
    2.times do |iteration|
      path = "/tmp/module-target-laraveltoken-fixed-owner-#{Process.pid}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      LaravelTokenTarget::WORKING_METHODS.each { |method| fixed_control(method, command, path, content) }
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      offset = rc_json('framework.instance_variable_get(:@laraveltoken_events).length')
      options = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'APP_KEY' => LaravelTokenTarget::KEY, 'SSL' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 10 }
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_fixed_owner) if iteration.positive?
      @selected_fixed_owner = selection
      events = rc_json("framework.instance_variable_get(:@laraveltoken_events).drop(#{offset})")
      proof = file(path)
      @rc[:calls] << { label: 'fixed-owner', iteration: iteration, options: options, output: output, selection: selection, command_base64: Base64.strict_encode64(command.b), events: events, denied: proof }
      rc_save
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      expect(events.select { |event| event['event'] == 'call' && event['method'] == 'exploit' }.length).to eq(1)
      expect(events.select { |event| event['event'] == 'call' && event['method'] == 'generate_token' }.map { |event| event.fetch('gadget') }).to eq([1, 2, 3, 4])
      responses = events.select { |event| event['event'] == 'return' && event['method'] == 'send_request_cgi' }.map { |event| event.fetch('response').fetch('code') }
      expect(responses).to eq([419, 419, 419, 419])
      expect(proof).to include('exists' => false)
    ensure
      rc_command('remove-fixed-owner-proof', 'target', 'rm', '-f', '--', path) if path
      expect(file(path)).to include('exists' => false) if path
      rc_save
    end
  end
end
