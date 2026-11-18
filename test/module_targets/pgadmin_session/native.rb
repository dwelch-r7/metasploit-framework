# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Native stock pgAdmin controls and source-scoped observation of owning calls.
module PgAdminSessionTarget
  include RsyncCredentialTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'pgadmin-session.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_owner
    'exploit/multi/http/pgadmin_session_deserialization'
  end

  def rc_resource_roles
    ['app']
  end

  def pa_native(phase)
    directory = File.join(target_runtime.fetch('artifacts'), 'native-' + phase)
    FileUtils.mkdir_p(directory)
    runtime = { directory: directory, compose: target_runtime.fetch('compose'), port: target_endpoint('app').fetch('port'), release: @release, prefix: @prefix, stamp: "#{Process.pid}-#{phase}" }
    path = File.join(directory, 'runtime.json')
    File.write(path, JSON.pretty_generate(runtime))
    stdout, stderr, status = Open3.capture3('python3', 'test/module_targets/pgadmin_session/native_control.py', path)
    File.write(File.join(directory, 'process.stdout'), stdout)
    File.write(File.join(directory, 'process.stderr'), stderr)
    expect(status.success?).to be(true), stderr
    proof = JSON.parse(File.read(File.join(directory, 'native-proof.json')))
    expect(proof.fetch('native_passed')).to be(true)
    @rc.fetch(:native) << { phase: phase, data: proof }
    rc_resources(phase)
    rc_save
  end

  def pa_call(label, options = {}, action: 'run -z', reuse: false)
    record = { label: label, options: options, action: action }
    @rc.fetch(:calls) << record
    defaults = { 'SSL' => false, 'TARGETURI' => @prefix + '/', 'USERNAME' => 'module-admin@example.com', 'PASSWORD' => 'module-target-password', 'AutoCheck' => true, 'PAYLOAD' => 'python/exec', 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 10 }
    selected = defaults.merge(options)
    selected['CMD'] = 'true' if selected['PAYLOAD'] == 'python/exec' && !selected.key?('CMD')
    run_target_module(rc_owner, 'app', selected, action: action, allow_errors: true, command_timeout: 90, reuse_module: reuse) do |output|
      record[:module_identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      record[:output_base64] = Base64.strict_encode64(output.b)
      rc_save
    end
  end

  def pa_file(path)
    code = "import base64,json;from pathlib import Path;import sys;p=Path(sys.argv[1]);s=p.stat() if p.is_file() else None;print(json.dumps({'exists':s is not None,'uid':s.st_uid if s else None,'base64':base64.b64encode(p.read_bytes()).decode() if s else None}))"
    output, = rc_command('inspect-file', 'app', '/venv/bin/python3', '-c', code, path)
    JSON.parse(output)
  end

  def pa_canary(label, username:, expected_execution:, force: false)
    marker = "/tmp/module-target-pgadmin-owner-#{Process.pid}-#{label}"
    expect(pa_file(marker).fetch('exists')).to be(false)
    output = pa_call(label, { 'USERNAME' => username, 'CMD' => 'printf %s pgadmin-owner > ' + marker, 'ForceExploit' => force })
    expect(output).to include('Successfully authenticated to pgAdmin', 'Serialized payload uploaded to:', 'Triggering deserialization for path:')
    expected = expected_execution ? { 'exists' => true, 'uid' => 5050, 'base64' => Base64.strict_encode64('pgadmin-owner') } : { 'exists' => false, 'uid' => nil, 'base64' => nil }
    begin
      rc_poll(5) { pa_file(marker) == expected }
    rescue RuntimeError
      expect(pa_file(marker)).to eq(expected)
    end
    @rc.fetch(:canaries) << { label: label, expected_execution: expected_execution, actual: pa_file(marker) }
    rc_save
  ensure
    rc_command('remove-owner-marker', 'app', 'rm', '-f', marker) if marker
    expect(pa_file(marker).fetch('exists')).to be(false) if marker
  end
end
