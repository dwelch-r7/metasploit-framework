require 'spec_helper'
require_relative '../../../test/module_targets/sudo_chroot/acceptance'

RSpec.describe SudoChrootTarget do
  subject(:target) do
    Object.new.extend(described_class).tap do |instance|
      instance.extend(RSpec::Matchers)
      instance.instance_variable_set(:@rc, { cases: [] })
    end
  end

  describe '#sc_state' do
    let(:captured) do
      path = File.expand_path('../../file_fixtures/modules/exploits/linux/local/sudo_chroot/kernel_time_wait.json', __dir__)
      JSON.parse(File.read(path)).fetch('observed_fields')
    end

    before { allow(target).to receive(:sc_native).with('state').and_return('processes' => [], 'connections' => [connection]) }

    context 'with the captured kernel TIME_WAIT record and no owned inode' do
      let(:connection) { captured }

      it 'does not classify it as a live leaked connection' do
        expect(target.sc_state.fetch('connections')).to eq([])
      end
    end

    context 'with an established owned socket' do
      let(:connection) { { 'state' => '01', 'inode' => '123' } }

      it 'keeps the leak criterion enabled' do
        expect(target.sc_state.fetch('connections')).to eq([connection])
      end
    end

    context 'with a half-closed owned socket' do
      let(:connection) { { 'state' => '08', 'inode' => '123' } }

      it 'keeps the leak criterion enabled' do
        expect(target.sc_state.fetch('connections')).to eq([connection])
      end
    end

    context 'with an unexpected nonzero inode on TIME_WAIT' do
      let(:connection) { { 'state' => '06', 'inode' => '123' } }

      it 'retains the unexpected owned record for investigation' do
        expect(target.sc_state.fetch('connections')).to eq([connection])
      end
    end
  end

  describe '#sc_case' do
    before do
      allow(target).to receive(:sc_idle).and_raise(IOError, 'Original native failure')
      allow(target).to receive(:sc_close_case).and_raise(IOError, 'Secondary cleanup failure')
      allow(target).to receive(:rc_save)
    end

    it 'preserves the original failure when cleanup also fails' do
      expect { target.sc_case('shell') }.to raise_error(IOError, 'Original native failure')
    end
  end
end
