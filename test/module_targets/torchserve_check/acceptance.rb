# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Gate real owner checks and refusal with independent vendor runtime controls.
module TorchserveCheckTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/http/torchserver_cve_2023_43654'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'torchserve-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def torchserve_native
    argv = ['python3', '-B', 'test/module_targets/torchserve_check/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    @rc[:native] = { argv: argv, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    value = JSON.parse(output)
    expect(value).to include('passed' => true, 'source_closed' => true, 'native_archives_removed' => true)
    expect(value.fetch('api_info')).to include('title' => 'TorchServe APIs', 'version' => ENV.fetch('TORCHSERVE_VERSION'))
    @rc[:calibrated] = true
    value
  end

  def torchserve_events(offset)
    rc_json("framework.instance_variable_get(:@torchserve_events).drop(#{offset})")
  end

  def torchserve_check
    offset = rc_json('framework.instance_variable_get(:@torchserve_events).length')
    output = run_target_module(OWNER, 'target', {}, action: 'check', allow_errors: true)
    events = torchserve_events(offset)
    @rc[:calls] << { action: 'check', output: output, events: events }
    rc_save
    version = ENV.fetch('TORCHSERVE_VERSION')
    fixed = version == '0.8.2'
    expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => fixed ? 'safe' : 'appears', 'reason' => "Version #{version} is #{fixed ? 'patched' : 'vulnerable'}." }])
    expect(events.select { |row| row['owner_exploit_body'] }).to eq([])
    expect(events.filter_map { |row| row['request'] }).to eq([{ 'method' => 'GET', 'uri' => '/api-description', 'vars_get' => nil }])
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(rc_json('framework.jobs.keys')).to eq([])
  end

  def torchserve_withhold
    2.times do |iteration|
      offset = rc_json('framework.instance_variable_get(:@torchserve_events).length')
      options = { 'AutoCheck' => true, 'ForceExploit' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 3 }
      output = run_target_module(OWNER, 'target', options, action: 'run -z', allow_errors: true, reuse_module: iteration.positive?)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@torchserve_selection) if iteration.positive?
      @torchserve_selection = selection
      events = torchserve_events(offset)
      @rc[:calls] << { action: 'autocheck-withhold', iteration: iteration, output: output, events: events, selection: selection }
      rc_save
      expect(output).to include('The target is not exploitable.')
      expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'Version 0.8.2 is patched.' }])
      expect(events.select { |row| row['owner_exploit_body'] || %w[generate_mar java_class_loader_start_service].include?(row['method']) }).to eq([])
      expect(events.filter_map { |row| row['request'] }).to eq([{ 'method' => 'GET', 'uri' => '/api-description', 'vars_get' => nil }])
      expect(rc_json('framework.sessions.keys')).to eq([])
      expect(rc_json('framework.jobs.keys')).to eq([])
    end
  end
end
