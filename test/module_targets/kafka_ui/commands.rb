# frozen_string_literal: true

require 'English'
require 'shellwords'
require 'uri'
require_relative '../rsync_creds/native'

# Actual owner commands after an independent same-byte native proof.
module KafkaUiCommandTarget
  include RsyncCredentialTarget

  def ku_native(operation, *)
    ks_native('native.py', operation, *)
  end

  def ku_file(path)
    output, = rc_command('native-file-state', 'app', 'sh', '-c', 'if [ -f "$1" ]; then stat -c "%u %s" "$1"; base64 "$1"; else printf "ABSENT\n"; fi', 'native-file', path)
    lines = output.lines.map(&:strip)
    return { 'exists' => false } if lines == ['ABSENT']

    uid, size = lines.fetch(0).split.map { |value| Integer(value, 10) }
    bytes = Base64.strict_decode64(lines.drop(1).join)
    expect(bytes.bytesize).to eq(size)
    { 'exists' => true, 'uid' => uid, 'base64' => Base64.strict_encode64(bytes) }
  end

  def ku_events
    rc_json('framework.instance_variable_get(:@kafka_ui_events)')
  end

  def ku_command(label, contents, auto_check:, reuse: false)
    positive = ENV.fetch('KAFKA_UI_EXPECT_GROOVY') == 'true'
    path = "/tmp/module-target-kafka-command-#{Process.pid}-#{label}"
    absent = !ku_file(path).fetch('exists')
    expect(absent).to be(true)
    offset = ku_events.length
    command = block_given? ? yield(path) : "printf %s #{Shellwords.escape(contents)} > #{path}"
    options = {
      'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command,
      'AutoCheck' => auto_check, 'ForceExploit' => false,
      'DisablePayloadHandler' => true, 'WfsDelay' => 0
    }
    ku_native('command_proof', options.fetch('CMD'), path, Base64.strict_encode64(contents.b))
    unless reuse
      console_command('back')
      expect(console_command('use exploit/linux/http/kafka_ui_unauth_rce_cve_2023_52251')).not_to match(/Failed to load|Unknown command|No results/)
    end
    expect(console_command('set PAYLOAD cmd/unix/generic')).not_to match(/Failed|Invalid|not found/)
    expect(rc_json("begin;active_module.datastore['CMD']=#{options.fetch('CMD').inspect};active_module.datastore['CMD'];end")).to eq(options.fetch('CMD'))
    record = { label: label, options: options, positive: positive, reuse: reuse, qualified: false }
    @rc[:calls] << record
    output = run_target_module('exploit/linux/http/kafka_ui_unauth_rce_cve_2023_52251', 'app', options.except('CMD'), action: 'run', allow_errors: true, reuse_module: true) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = ku_events.drop(offset)
      delivered = record.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'exploit' }
      record[:actual_datastore_input_matches] = delivered.all? { |event| event.fetch('datastore_command_base64') == Base64.strict_encode64(options.fetch('CMD').b) }
      rc_save
      expect(record.fetch(:actual_datastore_input_matches)).to be(true)
      executed = record.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'execute_command' }
      expect(executed.map { |event| event.fetch('command_base64') }).to eq([Base64.strict_encode64(options.fetch('CMD').b)])
    end
    record[:output_base64] = Base64.strict_encode64(output.b)
    record[:selection] = rc_json('active_module.object_id')
    record[:command_after_base64] = Base64.strict_encode64(rc_json("active_module.datastore['CMD']").b)
    expect(record.fetch(:command_after_base64)).to eq(Base64.strict_encode64(options.fetch('CMD').b))
    expect(record.fetch(:selection)).to eq(@previous_selection) if reuse
    @previous_selection = record.fetch(:selection)
    response = record.fetch(:events).reverse.find { |event| event['event'] == 'return' && event['method'] == 'execute_command' }&.[]('response')
    record[:execution_response] = response
    if positive
      expect(response).not_to be_nil, 'The module did not return a command response'
      expect(response.fetch('code')).to eq(200), 'The command endpoint rejected the request'
      rc_poll { ku_file(path).fetch('exists') }
      record[:proof] = ku_file(path)
      expect(record.fetch(:proof)).to eq('exists' => true, 'uid' => 100, 'base64' => Base64.strict_encode64(contents.b))
    else
      expect(output).to include('Exploit aborted due to failure: not-vulnerable:', 'filtering.groovy.enabled')
      record[:proof] = ku_file(path)
      expect(record.fetch(:proof)).to eq('exists' => false)
      expect(response).to include('code' => 400)
      rejection = JSON.parse(File.binread(File.join(target_runtime.fetch('artifacts'), response.fetch('file'))))
      expect(rejection).to include('code' => 4002, 'message' => include('filtering.groovy.enabled'))
    end
    record[:events] = ku_events.drop(offset)
    checks = record.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'check' }
    expect(checks.empty?).to eq(!auto_check)
    check_results = record.fetch(:events).select { |event| event['event'] == 'return' && event['method'] == 'check' }
    if auto_check
      expected_check = ENV.fetch('KAFKA_UI_VERSION') == '0.7.1' ? 'appears' : 'detected'
      expect(check_results.map { |event| event.fetch('check').fetch('code') }).to eq([expected_check])
    end
    # Framework AutoCheck allows both Appears and Detected; native disabled
    # filtering is proved by the target's explicit rejection after the attempt.
    reached = !auto_check || options.fetch('ForceExploit') || %w[vulnerable appears detected].include?(check_results.last&.dig('check', 'code'))
    exploit_calls = record.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'exploit' }
    expect(exploit_calls.length).to eq(reached ? 1 : 0)
    if reached
      expect(exploit_calls.first.fetch('datastore_command_base64')).to eq(Base64.strict_encode64(options.fetch('CMD').b))
      %w[get_cluster create_topic produce_message execute_command delete_topic].each do |name|
        expect(record.fetch(:events)).to include(include('event' => 'call', 'method' => name))
      end
      expected_script = record.fetch(:events).find { |event| event['event'] == 'call' && event['method'] == 'send_request_cgi' && event.fetch('request', {})['vars_get'] }&.dig('request', 'vars_get', 'q')
      wires = record.fetch(:events).select { |event| event['event'] == 'wire' }.filter_map do |event|
        bytes = File.binread(File.join(target_runtime.fetch('artifacts'), event.fetch('file')))
        expect(Digest::SHA256.hexdigest(bytes)).to eq(event.fetch('sha256'))
        method, request_target = bytes.lines.first.split(' ', 3)
        next unless method == 'GET' && request_target.include?('?')

        query = URI.decode_www_form(request_target.split('?', 2).last).to_h
        next unless query['filterQueryType'] == 'GROOVY_SCRIPT'

        { file: event.fetch('file'), target: request_target, decoded_query: query }
      end
      record[:command_wire] = wires
      expect(wires.length).to eq(1), 'Expected one actual socket write for the Groovy request'
      expect(wires.first.fetch(:target)).not_to include('\\')
      expect(wires.first.fetch(:decoded_query).fetch('q')).to eq(expected_script)
    end
    record[:execution_verified] = true
    rc_save
  ensure
    primary_error = $ERROR_INFO
    begin
      if absent
        rc_command('remove-command-proof', 'app', 'rm', '-f', path)
        expect(ku_file(path)).to eq('exists' => false)
      end
      ku_native('audit') if @rc && @rc[:initialized]
      if record
        record[:cleanup_verified] = true
        record[:qualified] = primary_error.nil? && record[:execution_verified] == true
      end
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc[:cleanup_errors] << { type: e.class.name, message: e.message, primary_error: primary_error&.message }
      raise unless primary_error
    ensure
      rc_save
    end
  end
end
