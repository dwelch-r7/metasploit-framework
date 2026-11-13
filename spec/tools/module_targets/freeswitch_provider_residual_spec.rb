require 'spec_helper'
require_relative '../../../test/module_targets/freeswitch_sessions/acceptance'

RSpec.describe Acceptance::FreeSwitchSessions do
  subject(:control) { Object.new.extend(described_class) }

  let(:defunct_provider) do
    { 'state' => 'Z', 'name' => 'freeswitch', 'ppid' => 7, 'uid' => 0, 'cmdline' => '', 'exe' => nil, 'connection_inodes' => [] }
  end

  before do
    control.instance_variable_set(:@engine_pid, 7)
    control.instance_variable_set(:@uid, '0')
  end

  it 'identifies only the exact observed native defunct launcher' do
    expect(control.ss_vendor_wrapper?(defunct_provider)).to be(true)
  end

  it 'retains a running application child as a real process' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('state' => 'S'))).to be(false)
  end

  it 'does not excuse a defunct payload process' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('name' => 'payload'))).to be(false)
  end

  it 'requires the verified engine parent' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('ppid' => 8))).to be(false)
  end

  it 'requires the verified service UID' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('uid' => 1))).to be(false)
  end

  it 'retains every socket-owning process' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('connection_inodes' => ['12345']))).to be(false)
  end

  it 'does not excuse a process with an executable' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('exe' => '/usr/local/freeswitch/bin/freeswitch'))).to be(false)
  end

  it 'does not excuse a process with an active command' do
    expect(control.ss_vendor_wrapper?(defunct_provider.merge('cmdline' => 'freeswitch -nf'))).to be(false)
  end
end
