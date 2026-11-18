# frozen_string_literal: true

require_relative '../netrc_creds/native'

# Reuses real shell/callback/recovery and CSV persistence observations unchanged.
module FetchmailCredentialTarget
  include NetrcCredentialTarget

  def rc_owner
    'post/multi/gather/fetchmailrc_creds'
  end

  def rc_resource_roles
    %w[linux reporting_db]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'fetchmail-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_native(phase)
    output, = rc_command(phase + '-native', 'linux', 'python3', '/opt/fetchmail-native.py', phase)
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(data.values_at('native_passed', 'hostname', 'uid')).to eq([true, 'module-target-fetchmail', 0])
    data
  end

  def fc_install(fixture, user = 'root', location: 'root')
    @fetchmail_case = { fixture: fixture, user: user, location: location }
    @rc.fetch(:case_states) << @fetchmail_case
    rc_save
    output, = rc_command('install-' + fixture, 'linux', 'python3', '/opt/fetchmail-case-state.py', 'install', fixture, location, user)
    @fetchmail_case[:native] = JSON.parse(output)
    rc_save
    expect(@fetchmail_case.fetch(:native).fetch('native_passed')).to be(true)
  end

  def fc_restore
    return unless @fetchmail_case

    output, = rc_command('restore-fetchmail', 'linux', 'python3', '/opt/fetchmail-case-state.py', 'restore', @fetchmail_case.fetch(:fixture), @fetchmail_case.fetch(:location), @fetchmail_case.fetch(:user))
    @fetchmail_case[:recovery] = JSON.parse(output)
    rc_save
    expect(@fetchmail_case.fetch(:recovery).fetch('absent')).to be(true)
    expect(@fetchmail_case.fetch(:recovery).fetch('was_present')).to be(true) if @fetchmail_case.key?(:native)
    @fetchmail_case = nil
  end

  def rc_observe_owner(label, _user)
    path = @fetchmail_case.fetch(:native).fetch('path')
    observed = rc_json('begin;require "base64";source="modules/post/multi/gather/fetchmailrc_creds.rb";{owner_sha256:Digest::SHA256.file(source).hexdigest,owner_source:active_module.method(:run).source_location,readable:active_module.readable?(' + path.inspect + '),bytes:active_module.read_file(' + path.inspect + ')&.then{|raw|Base64.strict_encode64(raw)}};end')
    @rc.fetch(:session_reads) << { label: label, path: path, data: observed }
    rc_save
    expect(observed.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/post/multi/gather/fetchmailrc_creds.rb').hexdigest)
    expect(File.realpath(observed.fetch('owner_source').first)).to eq(File.realpath('modules/post/multi/gather/fetchmailrc_creds.rb'))
    expect(observed.fetch('readable')).to eq(@fetchmail_case.fetch(:native).fetch('readable'))
    if observed.fetch('readable')
      expect(Digest::SHA256.hexdigest(Base64.strict_decode64(observed.fetch('bytes')))).to eq(@fetchmail_case.fetch(:native).fetch('sha256'))
    else
      expect(observed.fetch('bytes')).to be_nil
    end
  end

  def fc_call(label)
    nc_call(label)
  ensure
    call = @rc.fetch(:calls).last
    call[:fixture] = @fetchmail_case.fetch(:native) if call && call.fetch(:label) == label
    rc_save
  end

  def fc_verify(call)
    expect(call.fetch(:loot).length).to eq(1)
    row = call.fetch(:loot).first
    expect(row.values_at('ltype', 'content_type', 'info', 'address')).to eq(['fetchmailrc.creds', 'text/csv', '.fetchmailrc credentials', call.fetch(:session).fetch('host')])
    expect(row.fetch('csv').first).to eq(%w[Username Password Server Protocol Port])
    expect(row.fetch('csv').drop(1)).to match_array(call.fetch(:fixture).fetch('expected').map { |item| item.values_at('user', 'password', 'host', 'protocol', 'port') })
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('Post module execution completed', row.fetch('path'))
  end
end
