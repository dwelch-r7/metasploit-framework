# frozen_string_literal: true

require 'csv'
require_relative '../rsync_creds/native'

# Reuse the genuine shell, callback, reporting connection and recovery controls.
module NetrcCredentialTarget
  include RsyncCredentialTarget

  def rc_owner
    'post/multi/gather/netrc_creds'
  end

  def rc_resource_roles
    %w[linux auth reporting_db]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'netrc-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_native(phase)
    output, = rc_command(phase + '-native', 'linux', 'python3', '/opt/netrc-native.py')
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(data.fetch('native_passed')).to be(true)
    expect(data.values_at('hostname', 'uid')).to eq(['module-target-netrc-client', 0])
    data
  end

  def nc_install(fixture, user, location: 'root')
    @netrc_case = { fixture: fixture, user: user, location: location }
    @rc.fetch(:case_states) << @netrc_case
    rc_save
    output, = rc_command('install-' + fixture, 'linux', 'python3', '/opt/netrc-case-state.py', 'install', location, fixture, user)
    @netrc_case[:native] = JSON.parse(output)
    expect(@netrc_case.fetch(:native).fetch('native_passed')).to be(true)
    rc_save
  end

  def nc_restore
    return unless @netrc_case

    output, = rc_command('restore-netrc', 'linux', 'python3', '/opt/netrc-case-state.py', 'restore', @netrc_case.fetch(:location), @netrc_case.fetch(:fixture), @netrc_case.fetch(:user))
    data = JSON.parse(output)
    @netrc_case[:recovery] = data
    rc_save
    expect(data.fetch('absent')).to be(true)
    expect(data.fetch('was_present')).to be(true) if @netrc_case.key?(:native)
    @netrc_case = nil
  end

  def rc_observe_owner(label, _user)
    path = @netrc_case.fetch(:native).fetch('path')
    code = '{owner_sha256:Digest::SHA256.file("modules/post/multi/gather/netrc_creds.rb").hexdigest,owner_source:active_module.method(:run).source_location,readable:active_module.readable?(' + path.inspect + '),bytes:active_module.read_file(' + path.inspect + ')&.then{|raw|Base64.strict_encode64(raw)}}'
    observed = rc_json('begin;require "base64";' + code + ';end')
    @rc.fetch(:session_reads) << { label: label, path: path, data: observed }
    rc_save
    expect(observed.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/post/multi/gather/netrc_creds.rb').hexdigest)
    expect(File.realpath(observed.fetch('owner_source').first)).to eq(File.realpath('modules/post/multi/gather/netrc_creds.rb'))
    expect(observed.fetch('readable')).to eq(@netrc_case.fetch(:native).fetch('permissions').fetch('readable'))
    if observed.fetch('readable')
      expect(Digest::SHA256.hexdigest(Base64.strict_decode64(observed.fetch('bytes')))).to eq(@netrc_case.fetch(:native).fetch('sha256'))
    else
      expect(observed.fetch('bytes')).to be_nil
    end
  end

  def nc_reports
    expect(@workspace).to match(/\Arc_\d+_[a-z]+\z/)
    rows = JSON.parse(rc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT l.id,l.ltype,l.content_type,l.path,l.info,host(h.address::inet) AS address
        FROM loots l JOIN workspaces w ON w.id=l.workspace_id
        LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    rows.each do |row|
      path = File.realpath(row.fetch('path'))
      expect(path).to start_with(File.realpath(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/loot/')
      raw = File.binread(path)
      row['sha256'] = Digest::SHA256.hexdigest(raw)
      row['bytes_base64'] = Base64.strict_encode64(raw)
      row['csv'] = CSV.parse(raw)
    end
    cores = rc_sql("SELECT count(*) FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id WHERE w.name='#{@workspace}'").strip.to_i
    @rc.fetch(:reports) << { workspace: @workspace, loot: rows, credential_cores: cores }
    rc_save
    expect(cores).to eq(0)
    rows
  end

  def nc_call(label)
    prior = nc_reports.map { |row| row.fetch('id') }
    call = { label: label, workspace: @workspace, session: @session, started: true }
    @rc.fetch(:calls) << call
    run_target_module(rc_owner, 'linux', { 'SESSION' => @session.fetch('id') }, endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 120) do |output|
      call[:output_base64] = Base64.strict_encode64(output.b)
      call[:returned] = true
      call[:loot] = nc_reports.reject { |row| prior.include?(row.fetch('id')) }
      call[:module_id] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def nc_verify(call, hosts: ['netrc-auth'])
    expect(call.fetch(:loot).length).to eq(1)
    row = call.fetch(:loot).first
    expect(row.values_at('ltype', 'content_type', 'info', 'address')).to eq(['netrc.creds', 'text/csv', '.netrc credentials', call.fetch(:session).fetch('host')])
    expect(row.fetch('csv').first).to eq(%w[Username Password Server])
    expect(row.fetch('csv').drop(1)).to match_array(hosts.map { |host| ['module-test-user', 'module-test-password', host] })
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('Post module execution completed', row.fetch('path'))
  end
end
