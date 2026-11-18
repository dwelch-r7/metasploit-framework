# frozen_string_literal: true

require_relative '../generic_env/native'

# Reuses genuine callback/session, actor/process and exact-loot controls.
module GpgCredentialTarget
  include GenericEnvironmentTarget

  def rc_owner
    'post/multi/gather/gpg_creds'
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'gpg-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def gp_native(phase)
    output, = rc_command(phase + '-state', 'linux', 'python3', '/opt/state.py')
    state = JSON.parse(output)
    expect(state.values_at('hostname', 'uid')).to eq(['module-target-gpg', 0])
    output, = rc_command(phase + '-gpg-controls', 'linux', 'python3', '/opt/fixture_native.py')
    controls = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, state: state, data: controls }
    rc_save
    expect(controls.values_at('native_passed', 'owner_calls')).to eq([true, 0])
    expect(controls.fetch('controls').length).to eq(4)
    state
  end

  def gp_missing
    @gpg_case = { missing: true }
    @rc.fetch(:gpg_cases) << @gpg_case
    output, = rc_command('missing-gpg', 'linux', 'python3', '/opt/gpg-case-state.py', 'missing')
    @gpg_case[:native] = JSON.parse(output)
    rc_save
    expect(@gpg_case.fetch(:native).values_at('native_passed', 'missing')).to eq([true, true])
  end

  def gp_install(holder, protection, viewer = 'root', unreadable: false, empty: false)
    @gpg_case = { holder: holder, protection: protection, viewer: viewer }
    @rc.fetch(:gpg_cases) << @gpg_case
    output, = rc_command('install-gpg', 'linux', 'python3', '/opt/gpg-case-state.py', 'install', holder, viewer, protection, unreadable ? 'unreadable' : 'normal', empty ? 'empty' : 'noempty')
    @gpg_case[:native] = JSON.parse(output)
    rc_save
    expect(@gpg_case.fetch(:native).fetch('native_passed')).to be(true)
  end

  def gp_restore
    return unless @gpg_case

    output, = rc_command('restore-gpg', 'linux', 'python3', '/opt/gpg-case-state.py', 'restore')
    @gpg_case[:recovery] = JSON.parse(output)
    rc_save
    expect(@gpg_case.fetch(:recovery).fetch('absent')).to be(true)
    expect(@gpg_case.fetch(:recovery).fetch('was_present')).to eq(!@gpg_case.fetch(:native).fetch('missing', false)) if @gpg_case.key?(:native)
    @gpg_case = nil
  end

  def gp_call(label)
    prior = ge_reports.map { |row| row.fetch('id') }
    call = { label: label, session: @session, fixture: @gpg_case.fetch(:native), channels_before: ge_channels }
    @rc.fetch(:calls) << call
    rc_save
    run_target_module(rc_owner, 'linux', { 'SESSION' => @session.fetch('id') }, endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 120) do |output|
      call[:output_base64] = Base64.strict_encode64(output.b)
      call[:returned] = true
      call[:loot] = ge_reports.reject { |row| prior.include?(row.fetch('id')) }
      call[:channels_after] = ge_channels
      call[:descendants_after] = ge_descendants
      call[:module_id] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def gp_verify(call)
    expected = call.fetch(:fixture).fetch('files').values.select { |row| row.fetch('expected_collect') }
    expect(call.fetch(:returned)).to be(true)
    expect(call.fetch(:loot).length).to eq(expected.length)
    actual = call.fetch(:loot).map do |row|
      expect(row.values_at('content_type', 'address')).to eq(['text/plain', call.fetch(:session).fetch('host')])
      [row.fetch('ltype'), row.fetch('info'), row.fetch('base64')]
    end
    expected = expected.map do |row|
      name = File.basename(row.fetch('path'))
      type = name == 'trustdb.gpg' ? 'trustdb' : name
      ['gpg.' + type, 'GnuPG ' + name + ' File', row.fetch('base64')]
    end
    expect(actual.sort).to eq(expected.sort)
    output = Base64.strict_decode64(call.fetch(:output_base64))
    expect(output).to include('Post module execution completed')
    expect(output).not_to match(/Post failed|Error running command|NoMethodError|RuntimeError|Rex::TimeoutError|Exception/)
    call.fetch(:loot).each { |row| expect(output).to include('File stored in: ' + row.fetch('path')) }
    expect(call.fetch(:channels_after)).to eq(call.fetch(:channels_before))
    expect(call.fetch(:descendants_after)).to eq([])
  end
end
