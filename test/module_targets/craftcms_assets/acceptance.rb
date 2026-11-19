# frozen_string_literal: true

require_relative '../craftcms/acceptance'
require_relative '../craftcms_ftp/session_prerequisites'

# Real application gates and passive evidence shared by the image-transform profiles.
module CraftAssetTarget
  OWNER = 'exploit/linux/http/craftcms_preauth_rce_cve_2025_32432'

  def rc_resource_roles
    %w[app reporting_db framework]
  end

  def cc_port
    cf_port
  end

  def ca_native(operation, phase)
    output, status = rc_command(phase + '-native-assets', 'app', 'python3', '/opt/module-target/native-assets.py', @profile_name, operation, required: false)
    record = { operation: operation, phase: phase, exit: status, output_base64: Base64.strict_encode64(output.b) }
    @rc[:asset_native] << record
    rc_save
    expect(status).to eq(0), output
    data = JSON.parse(output)
    record[:data] = data
    expect(data).to include('passed' => true)
    @rc.fetch(:native) << { phase: phase, data: data.fetch('data').fetch('native_core') } if operation == 'audit'
    data.fetch('data')
  end

  def ca_events
    rc_json('framework.instance_variable_get(:@craft_asset_events)')
  end

  def ca_session_files
    output, = rc_command('native-session-file-names', 'app', 'python3', '-c', 'import json,sys;from pathlib import Path;print(json.dumps(sorted(p.name for p in Path(sys.argv[1]).glob("sess_*") if p.is_file())))', @session_root)
    JSON.parse(output)
  end

  def ca_setup
    @profile_name = ENV.fetch('CRAFT_PROFILE')
    @profile = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).fetch('profiles').fetch(@profile_name)
    @rc = { commands: [], native: [], calls: [], sessions: [], session_attempts: [], reports: [], interrupted_session_cleanup: [], cleanup_errors: [], operator_cleanup: [], snapshots: [], asset_native: [] }
    rc_resources('before')
    setup = ca_native('initialize', 'setup')
    @asset = setup.fetch('baseline').fetch('asset')
    ca_native('audit', 'before')
    session = ca_native('session', 'before')
    @session_root = File.dirname(session.fetch('return_url_session').fetch('path'))
    @rc[:native_session_configuration] = session.fetch('configuration')
    @baseline = cc_snapshot
    endpoint = target_runtime.fetch('module_endpoints').fetch('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('setg LHOST ' + listener_host)).not_to include('[-]')
    @rc[:callback] = { host: listener_host, bind: '0.0.0.0' }
    cc_install_payload_runtime
    @rc[:observer] = rc_json("begin;load 'test/module_targets/craftcms_assets/observe.rb';CraftAssetObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
  end

  def ca_cleanup_sessions(events, before)
    events.filter_map { |event| event['session'] }.uniq { |row| row.fetch('sid') }.each do |session|
      sid = session.fetch('sid')
      next unless sid.match?(/\A[A-Za-z0-9,-]{1,128}\z/) && !before.include?('sess_' + sid)

      file = File.join(@session_root, 'sess_' + sid)
      value = it_file(file)
      @rc.fetch(:operator_cleanup) << { kind: 'owned_php_session', path: file, value: value }
      next unless value.fetch('exists') && value.fetch('uid') == it_expected_uid

      rc_command('remove-owned-operator-session', 'app', 'rm', '-f', file)
      expect(it_file(file)).to include('exists' => false)
    end
  end

  def ca_command(label, automatic, target:, reuse: false, options: {}, positive: true)
    @workspace = "craft_#{Process.pid}_asset#{label}"
    expect(console_command('workspace -a ' + @workspace)).not_to include('[-]')
    unless reuse
      console_command('back')
      expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command/)
    end
    selected = rc_json('active_module.object_id')
    expect(selected).to eq(@ca_previous_instance) if reuse
    @ca_previous_instance = selected
    console_command('set TARGET ' + target.to_s)
    console_command('set PAYLOAD ' + (target.zero? ? 'php/exec' : 'cmd/unix/generic'))
    path = "/tmp/module-target-craftasset-owner-#{Process.pid}-#{label}"
    absent = !it_file(path).fetch('exists')
    expect(absent).to be(true)
    contents = "craftasset owner '#{label}' % $ ; \\ end"
    quoted = "'" + contents.gsub("'", %q{'"'"'}) + "'"
    command = "printf %s #{quoted} > #{path}"
    expect(rc_json("begin;active_module.datastore['CMD']=#{command.inspect};active_module.datastore['CMD'];end")).to eq(command)
    before = ca_session_files
    offset = ca_events.length
    record = { label: label, auto_check: automatic, owner: OWNER, target: target, selected_instance: selected, repeat: reuse, options: options, positive_expected: positive, command_base64: Base64.strict_encode64(command.b) }
    @rc.fetch(:calls) << record
    values = { 'ASSET_ID' => @asset.fetch('id'), 'AutoCheck' => automatic, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }.merge(options)
    output = run_target_module(OWNER, 'app', values, action: 'run -z', reuse_module: true, allow_errors: true)
    record[:output_base64] = Base64.strict_encode64(output.b)
    record[:events] = ca_events.drop(offset)
    record[:proof] = it_file(path)
    record[:command_after_base64] = Base64.strict_encode64(rc_json("active_module.datastore['CMD']").b)
    rc_save
    expect(record.fetch(:command_after_base64)).to eq(record.fetch(:command_base64))
    if positive
      expect(record.fetch(:proof)).to eq('exists' => true, 'uid' => it_expected_uid, 'base64' => Base64.strict_encode64(contents))
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
    else
      expect(record.fetch(:proof)).to include('exists' => false)
      expect(output).to include('Exploit aborted')
    end
    check_calls = record.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'check' }
    expect(check_calls.empty?).to eq(!automatic)
    record
  ensure
    primary = $ERROR_INFO
    begin
      if record
        record[:events] = ca_events.drop(offset)
        record[:final_console_base64] = Base64.strict_encode64(console.all_data.b)
        ca_cleanup_sessions(record.fetch(:events), before)
      end
      console_command('jobs -K')
      console_command('sessions -K')
      if absent
        rc_command('remove-owned-command-proof', 'app', 'rm', '-f', path)
        expect(it_file(path)).to include('exists' => false)
      end
      expect(cc_snapshot).to eq(@baseline) if @baseline
      rc_resources('after-owner')
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { type: e.class.name, message: e.message, primary_error: primary&.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def ca_final_audit
    return unless @baseline

    File.write(File.join(target_runtime.fetch('artifacts'), 'native-craft-after.started'), Time.now.utc.iso8601)
    ca_native('audit', 'after')
    expect(cc_snapshot).to eq(@baseline)
    rc_resources('after')
  ensure
    rc_save
  end
end
