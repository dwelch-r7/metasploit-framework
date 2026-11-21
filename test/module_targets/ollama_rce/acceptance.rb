# frozen_string_literal: true

require_relative '../rsync_creds/native'
require 'net/http'
require 'uri'

# Native-calibrated real owner check, command execution and fixed refusal.
module OllamaRceTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/http/ollama_rce_cve_2024_37032'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'ollama-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def ollama_http(role, path, data = nil, method: nil)
    uri = URI(@rc[:native_result].fetch('endpoints').fetch(role) + path)
    request = Net::HTTPGenericRequest.new(method || (data ? 'POST' : 'GET'), !data.nil?, true, uri.request_uri, 'Content-Type' => 'application/json')
    request.body = JSON.generate(data) if data
    response = Net::HTTP.start(uri.host, uri.port, nil, open_timeout: 3, read_timeout: 10) { |http| http.request(request) }
    value = JSON.parse(response.body)
    @rc[:http] << { role: role, path: path, method: request.method, status: response.code, value: value }
    rc_save
    expect(response.code).to eq('200'), value.inspect
    value
  end

  def ollama_file(path)
    ollama_http('observer', '/file?' + URI.encode_www_form(path: path))
  end

  def ollama_remove(paths)
    ollama_http('observer', '/remove', { paths: paths })
    paths.each { |path| expect(ollama_file(path)).to eq('exists' => false) }
  end

  def ollama_resources(phase)
    snapshot = ollama_http('observer', '/snapshot')
    @rc[:resources] << { phase: phase, snapshot: snapshot }
    rc_save
    expect(snapshot.fetch('resources').fetch('memory.events').values_at('oom', 'oom_kill', 'max')).to eq(%w[0 0 0])
    expect(snapshot.fetch('resources').fetch('pids.events').fetch('max')).to eq('0')
    expect(snapshot.fetch('backend_exit')).to be_nil
    expect(snapshot.fetch('preload')).to eq('exists' => false)
    snapshot
  end

  def ollama_native
    argv = ['python3', '-B', 'test/module_targets/ollama_rce/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    @rc[:native] = { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    @rc[:native_result] = JSON.parse(output)
    expect(@rc[:native_result]).to include('passed' => true, 'registry_closed' => true, 'version' => ENV.fetch('OLLAMA_VERSION'))
    expect(@rc[:native_result].fetch('fixed_denial')).to eq(ENV.fetch('OLLAMA_VERSION') == '0.1.34')
    @rc[:calibrated] = true
    @rc[:observer] = rc_json("begin;load 'test/module_targets/ollama_rce/observe.rb';OllamaObservation.install(framework,#{target_runtime.fetch('artifacts').inspect},#{@rc[:native_result].fetch('endpoints').fetch('observer').inspect});end")
    ollama_resources('before-owner')
  end

  def ollama_events(offset)
    rc_json("framework.instance_variable_get(:@ollama_events).drop(#{offset})")
  end

  def ollama_check
    offset = rc_json('framework.instance_variable_get(:@ollama_events).length')
    output = run_target_module(OWNER, 'target', {}, action: 'check', allow_errors: true)
    events = ollama_events(offset)
    @rc[:calls] << { action: 'check', output: output, events: events }
    rc_save
    fixed = ENV.fetch('OLLAMA_VERSION') == '0.1.34'
    reason = fixed ? 'Ollama 0.1.34 (patched)' : 'Ollama 0.1.33 (vulnerable to path traversal)'
    expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => fixed ? 'safe' : 'appears', 'reason' => reason }])
    expect(events.select { |row| row['owner_exploit_body'] }).to eq([])
    expect(events.filter_map { |row| row['request'] }).to eq([{ 'method' => 'GET', 'uri' => '/api/version', 'data' => nil }])
  end

  def ollama_command(iteration)
    proof = "/tmp/module-target-ollama/owner/proof-#{iteration}"
    marker = "Owner #{iteration} 'quote' \\ Unicode雪\r\nEnd\n".encode(Encoding::UTF_8).b
    expect(ollama_file(proof)).to eq('exists' => false)
    offset = rc_json('framework.instance_variable_get(:@ollama_events).length')
    options = {
      'PAYLOAD' => 'linux/x64/exec', 'CMD' => "printf %s #{Base64.strict_encode64(marker)} | base64 -d > #{proof}",
      'SRVHOST' => '0.0.0.0', 'SRVPORT' => 4493, 'URIHOST' => @rc[:native_result].fetch('endpoints').fetch('callback_host'),
      'WRITABLE_DIR' => '/tmp/module-target-ollama/owner', 'AllowNoCleanup' => true,
      'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 5
    }
    output = run_target_module(OWNER, 'target', options, action: 'run -z', allow_errors: true, reuse_module: iteration.positive?, command_timeout: 90)
    selection = rc_json('active_module.object_id')
    expect(selection).to eq(@rc[:selection]) if iteration.positive?
    @rc[:selection] = selection
    events = ollama_events(offset)
    @rc[:calls] << { action: 'command', iteration: iteration, selection: selection, output: output, events: events }
    rc_save
    prepared = events.filter_map { |row| row['prepared'] }.fetch(0)
    @rc[:recovery_paths] |= [proof, prepared.fetch('so_path')]
    library = Base64.strict_decode64(events.filter_map { |row| row['library_base64'] }.fetch(0))
    expect(library).to start_with("\x7fELF".b)
    expect(Base64.strict_decode64(ollama_file(prepared.fetch('so_path')).fetch('base64'))).to eq(library)
    before_trigger = events.filter_map { |row| row['before_trigger'] }.fetch(0)
    expect(Base64.strict_decode64(before_trigger.fetch('preload').fetch('base64'))).to eq(prepared.fetch('preload_blob').b)
    expect(before_trigger.fetch('proof')).to eq('exists' => false)
    expect(events.count { |row| row['owner_exploit_body'] }).to eq(1)
    expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => 'appears', 'reason' => 'Ollama 0.1.33 (vulnerable to path traversal)' }])
    physical = rc_poll(8) do
      value = ollama_file(proof)
      value if value.fetch('exists')
    end
    expect(physical.fetch('uid')).to eq(0)
    expect(Base64.strict_decode64(physical.fetch('base64'))).to eq(marker)
    expect(ollama_http('api', '/api/tags').fetch('models')).to eq([])
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    ollama_resources('after-command-' + iteration.to_s)
    # Sessionless command payloads cannot provide FileDropper's session API.
    # Record its remaining library before explicit resident fixture recovery.
    ollama_remove([proof, prepared.fetch('so_path')])
    @rc[:recovery_paths] -= [proof, prepared.fetch('so_path')]
  end

  def ollama_withhold
    2.times do |iteration|
      offset = rc_json('framework.instance_variable_get(:@ollama_events).length')
      output = run_target_module(OWNER, 'target', { 'AutoCheck' => true, 'ForceExploit' => false, 'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0 }, action: 'run -z', allow_errors: true, reuse_module: iteration.positive?)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@rc[:selection]) if iteration.positive?
      @rc[:selection] = selection
      events = ollama_events(offset)
      @rc[:calls] << { action: 'withhold', iteration: iteration, output: output, events: events }
      rc_save
      expect(output).to include('The target is not exploitable.')
      expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'Ollama 0.1.34 (patched)' }])
      expect(events.select { |row| row['owner_exploit_body'] || row['library_base64'] || row['prepared'] || row['before_trigger'] }).to eq([])
      expect(events.filter_map { |row| row['request'] }).to eq([{ 'method' => 'GET', 'uri' => '/api/version', 'data' => nil }])
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    end
  end
end
