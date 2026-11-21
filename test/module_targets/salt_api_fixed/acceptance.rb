# frozen_string_literal: true

require_relative '../salt_api/acceptance'

# Keep auth-only detection distinct from the command-injection prerequisite.
module SaltApiFixedTarget
  include SaltApiTarget

  def sf_version
    family = File.basename(target_runtime.fetch('artifacts'))
    raise ArgumentError, 'Unexpected Salt fixed-release profile' unless family.match?(/\Asalt_api_3000_[45]\z/)

    family.delete_prefix('salt_api_').tr('_', '.')
  end

  def sf_ready
    rc_resources('before')
    argv = ['python3', '-B', 'test/module_targets/salt_api_fixed/native_probe.py', sf_version]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    @rc[:readiness] = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'salt-api-fixed-native.json')))
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'module_invoked' => false, 'version' => sf_version)
    expect(sa_observe('artifacts')).to eq('exists' => false)
    @rc[:before_owner] = sa_observe('snapshot')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/salt_api/observe.rb';SaltApiObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    rc_save
  end

  def sf_checks
    calls = 2.times.map { |index| sa_call('fixed-check-' + index.to_s, reuse: index.positive?) }
    expect(calls.map { |call| call.fetch(:selection) }.uniq.length).to eq(1)
    calls.each do |call|
      checks = sa_events(call, 'check', 'return').map { |row| row.fetch('check') }
      expect(checks.length).to eq(1)
      expect(sa_events(call, 'exploit')).to eq([])
      if sf_version == '3000.5'
        expect(checks).to eq([{ 'code' => 'safe', 'reason' => 'Auth bypass failed.' }])
      else
        expect(%w[vulnerable appears]).not_to include(checks.first.fetch('code')), "Command injection was natively blocked, but the module returned #{checks.inspect}"
      end
    end
  end

  def sf_autocheck
    entry = @rc.fetch(:readiness).fetch('command')
    options = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => entry.fetch('command'), 'AutoCheck' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
    calls = 2.times.map do |index|
      expect(sa_observe('proof', entry.fetch('path'))).to eq('exists' => false)
      call = sa_call('fixed-autocheck-' + index.to_s, options, action: 'run', reuse: index.positive?)
      call[:proof] = sa_observe('proof', entry.fetch('path'))
      rc_save
      call
    end
    expect(calls.map { |call| call.fetch(:selection) }.uniq.length).to eq(1)
    calls.each do |call|
      expect(call.fetch(:proof)).to eq('exists' => false)
      expect(sa_events(call, 'exploit')).to eq([])
      expect(sa_events(call, 'execute_command')).to eq([])
      expect(call.fetch(:output)).to include('Exploit aborted due to failure')
    end
  end
end
