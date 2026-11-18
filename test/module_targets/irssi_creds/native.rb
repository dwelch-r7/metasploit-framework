# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Uses the unchanged genuine shell, callback, reporting and recovery controls.
module IrssiCredentialTarget
  include RsyncCredentialTarget

  def rc_owner
    'post/multi/gather/irssi_creds'
  end

  def rc_resource_roles
    %w[linux reporting_db]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'irssi-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_native(phase)
    output, = rc_command(phase + '-native', 'linux', 'python3', '/opt/irssi-native.py', phase)
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(data.values_at('native_passed', 'hostname', 'uid')).to eq([true, 'module-target-irssi', 0])
    data
  end

  def ic_install(fixture, user = 'root', location: 'root', unreadable: false)
    @irssi_case = { fixture: fixture, user: user, location: location, unreadable: unreadable }
    @rc.fetch(:case_states) << @irssi_case
    rc_save
    output, = rc_command('install-' + fixture, 'linux', 'python3', '/opt/irssi-case-state.py', 'install', fixture, location, user, unreadable ? 'unreadable' : 'normal')
    @irssi_case[:native] = JSON.parse(output)
    rc_save
    expect(@irssi_case.fetch(:native).fetch('native_passed')).to be(true)
  end

  def ic_restore
    return unless @irssi_case

    output, = rc_command('restore-irssi', 'linux', 'python3', '/opt/irssi-case-state.py', 'restore', @irssi_case.fetch(:fixture), @irssi_case.fetch(:location), @irssi_case.fetch(:user))
    @irssi_case[:recovery] = JSON.parse(output)
    rc_save
    expect(@irssi_case.fetch(:recovery).values_at('absent', 'directory_absent')).to eq([true, true])
    expect(@irssi_case.fetch(:recovery).fetch('was_present')).to be(true) if @irssi_case.key?(:native)
    @irssi_case = nil
  end

  def rc_observe_owner(label, _user)
    path = @irssi_case.fetch(:native).fetch('path')
    observed = rc_json('begin;require "base64";source="modules/post/multi/gather/irssi_creds.rb";{owner_sha256:Digest::SHA256.file(source).hexdigest,owner_source:active_module.method(:run).source_location,file_exists:active_module.file?(' + path.inspect + '),readable:active_module.readable?(' + path.inspect + '),bytes:active_module.read_file(' + path.inspect + ')&.then{|raw|Base64.strict_encode64(raw)}};end')
    @rc.fetch(:session_reads) << { label: label, path: path, data: observed }
    rc_save
    expect(observed.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/post/multi/gather/irssi_creds.rb').hexdigest)
    expect(File.realpath(observed.fetch('owner_source').first)).to eq(File.realpath('modules/post/multi/gather/irssi_creds.rb'))
    expect(observed.fetch('file_exists')).to eq(@irssi_case.fetch(:native).fetch('file_exists'))
    expect(observed.fetch('readable')).to eq(@irssi_case.fetch(:native).fetch('readable'))
    if observed.fetch('readable')
      expect(Digest::SHA256.hexdigest(Base64.strict_decode64(observed.fetch('bytes')))).to eq(@irssi_case.fetch(:native).fetch('sha256'))
    else
      expect(observed.fetch('bytes')).to be_nil
    end
  end

  def ic_reports
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
      row['base64'] = Base64.strict_encode64(raw)
      row['sha256'] = Digest::SHA256.hexdigest(raw)
    end
    cores = rc_sql("SELECT count(*) FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id WHERE w.name='#{@workspace}'").strip.to_i
    @rc.fetch(:reports) << { workspace: @workspace, loot: rows, credential_cores: cores }
    rc_save
    expect(cores).to eq(0)
    rows
  end

  def ic_call(label)
    prior = ic_reports.map { |row| row.fetch('id') }
    call = { label: label, workspace: @workspace, session: @session, fixture: @irssi_case.fetch(:native), started: true }
    @rc.fetch(:calls) << call
    run_target_module(rc_owner, 'linux', { 'SESSION' => @session.fetch('id') }, endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 120) do |output|
      call[:output_base64] = Base64.strict_encode64(output.b)
      call[:returned] = true
      call[:loot] = ic_reports.reject { |row| prior.include?(row.fetch('id')) }
      call[:module_id] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def ic_verify(call)
    unless call.fetch(:fixture).fetch('readable') && call.fetch(:fixture).fetch('expected_passwords').any?
      expect(call.fetch(:loot)).to eq([])
      expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('Post module execution completed')
      return
    end

    expect(call.fetch(:loot).length).to eq(1)
    row = call.fetch(:loot).first
    expect(row.values_at('ltype', 'content_type', 'info', 'address')).to eq(['irssi config file', 'text/plain', 'IRC Password', call.fetch(:session).fetch('host')])
    expect(row.fetch('base64')).to eq(call.fetch(:fixture).fetch('base64'))
    output = Base64.strict_decode64(call.fetch(:output_base64))
    expect(output).to include('Post module execution completed', row.fetch('path'))
    call.fetch(:fixture).fetch('expected_passwords').each { |password| expect(output).to include(password) }
  end
end
