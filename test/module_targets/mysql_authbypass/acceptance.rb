# frozen_string_literal: true

require 'csv'
require_relative '../rsync_creds/native'

# Native authentication, exact CSV and selected connection/reporting recovery.
module MysqlAuthbypassTarget
  include RsyncCredentialTarget

  OWNER = 'auxiliary/scanner/mysql/mysql_authbypass_hashdump'

  def rc_owner
    OWNER
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'mysql-authbypass.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def ma_native(mode)
    output, = rc_command('native-' + mode, 'app', 'bash', '/opt/module-target/native.sh', @native_peer, mode)
    output
  end

  def ma_gate(phase)
    rc_resources(phase)
    output = ma_native('probe')
    expect(output).to include('MODULE_TARGET_NATIVE_LOGIN')
    case @mode
    when 'vulnerable'
      expect(output).to include("5.5.23\troot@%\tMODULE_TARGET_NATIVE_LOGIN", 'NATIVE_WRONG_PASSWORD_ACCEPTED', 'ERROR 1142')
    when 'open'
      expect(output).to include('NATIVE_GRANTS_DISABLED', '5.5.23')
    when 'policy'
      expect(output).to include('NATIVE_HOST_POLICY_DENIED', 'ERROR 1130', '5.5.23')
    when 'fixed'
      expect(output).to include('NATIVE_PATCHED_PASSWORD_DENIAL', '11.2.2-MariaDB', 'ERROR 1142')
    end
    @rc.fetch(:native) << { phase: phase, output_base64: Base64.strict_encode64(output.b) }
    expect(ma_native('state')).to eq(@state) if @state
    ma_idle
    rc_save
  end

  def ma_idle
    rc_poll(8) { ma_native('idle').strip == '0' }
  end

  def ma_call(label, username: 'root', reuse: false, options: {})
    record = { label: label, username: username }
    @rc.fetch(:calls) << record
    before = rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|p|File.file?(p)}')
    output = run_target_module(OWNER, 'app', { 'USERNAME' => username, 'THREADS' => 1, 'ConnectTimeout' => 3 }.merge(options), allow_errors: true, reuse_module: reuse, command_timeout: 90) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      rc_save
    end
    paths = rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|p|File.file?(p)}') - before
    record[:loot_paths] = paths
    rc_save
    ma_idle
    expect(ma_native('state')).to eq(@state)
    [output, paths]
  end

  def ma_acquire(label, username: 'root', reuse: false)
    # The genuine defect is probabilistic. Retain every exhausted 1,000-try run;
    # retry only that explicit outcome, never a query/parser/cleanup error.
    3.times do |attempt|
      output, paths = ma_call("#{label}-#{attempt + 1}", username: username, reuse: reuse || attempt.positive?)
      return [output, paths] unless output.include?('Unable to bypass authentication, this target may not be vulnerable')

      expect(paths).to eq([])
      ma_gate('after-exhaustion')
    end
    raise 'No authentication bypass within three bounded owner runs; acquisition remains unqualified'
  end

  def ma_services
    expect(@workspace).to match(/\Amysql_bypass_\d+_[a-z]+\z/)
    rows = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.name,s.proto,host(h.address::inet) AS address,s.port FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
    @rc.fetch(:reports) << { workspace: @workspace, services: rows }
    rc_save
    rows
  end

  def ma_hashes(label, username: 'root', reuse: false)
    output, paths = ma_acquire(label, username: username, reuse: reuse)
    expect(output).to include('Hash Table has been saved:')
    expect(ma_services).to eq([{ 'name' => 'mysql', 'proto' => 'tcp', 'address' => target_endpoint('app').fetch('host'), 'port' => target_endpoint('app').fetch('port') }])
    expect(paths.length).to eq(1)
    rows = CSV.parse(File.binread(paths.first), headers: true)
    expect(rows.headers).to eq(%w[Username Hash])
    expect(rows.map(&:fields).sort).to eq(@expected.sort)
    @rc.fetch(:loots) << { label: label, path: paths.first, sha256: Digest::SHA256.file(paths.first).hexdigest }
    rc_save
  end
end
