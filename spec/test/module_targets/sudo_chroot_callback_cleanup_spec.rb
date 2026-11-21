require 'spec_helper'
require_relative '../../../test/module_targets/sudo_chroot_sessions/acceptance'

RSpec.describe SudoChrootSessions do
  subject(:target) do
    Object.new.extend(described_class).tap do |instance|
      instance.extend(RSpec::Matchers)
      instance.instance_variable_set(:@sc_case, {})
    end
  end

  let(:cleanup_error) { IOError.new('Callback transport failed during cleanup') }

  before do
    allow(target).to receive(:rc_save)
    allow(target).to receive(:sc_native).with('file', '/tmp/module-target-sudo-native-callback-log').and_raise(original_error)
    allow(target).to receive(:ss_close).and_raise(cleanup_error)
  end

  context 'when native observation raises an operation error' do
    let(:original_error) { IOError.new('Original native observation failure') }

    it 'preserves that exact error when remote shutdown also fails' do
      expect { target.ss_control({}) }.to(raise_error { |error| expect(error).to equal(original_error) })
    end
  end

  context 'when native observation raises an assertion error' do
    let(:original_error) { RSpec::Expectations::ExpectationNotMetError.new('Original native control assertion') }

    it 'preserves that exact assertion when remote shutdown also fails' do
      expect { target.ss_control({}) }.to(raise_error { |error| expect(error).to equal(original_error) })
    end
  end
end
