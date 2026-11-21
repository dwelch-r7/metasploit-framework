require 'spec_helper'
require_relative '../../../test/module_targets/sudo_chroot_sessions/acceptance'

RSpec.describe SudoChrootSessions, '#ss_session' do
  subject(:target) { Object.new.extend(described_class).extend(RSpec::Matchers) }

  let(:fixture) do
    path = File.expand_path('../../file_fixtures/modules/exploits/linux/local/sudo_chroot/callback_cwd.json', __dir__)
    JSON.parse(File.read(path))
  end
  let(:capture) { fixture.fetch('valid') }
  let(:attempt) { { cwd: capture.fetch('entry_cwd') } }

  before do
    allow(target).to receive(:rc_save)
    allow(target).to receive(:rc_poll).with(30).and_return('id' => capture.fetch('proof').fetch('id'))
    allow(target).to receive(:rc_json).and_return(capture.fetch('proof'), capture.fetch('callback_cwd'), capture.fetch('relative_api'))
    allow(target).to receive(:sc_native).with('file', anything).and_return(capture.fetch('physical_proof'))
    allow(target).to receive(:sc_native).with('remove', anything).and_return('exists' => false)
    allow(target).to receive(:ss_native).with('session-cwd', capture.fetch('proof').fetch('pid')).and_return(capture.fetch('physical_session'))
  end

  it 'retains the real entry cwd separately from the observed callback cwd' do
    target.ss_session(attempt, SudoChrootTarget::OWNER, 0, expected_cwd: '/tmp')

    expect(attempt).to include(cwd: '/home/lab', callback_cwd: '/tmp')
  end

  context 'with the captured original deleted callback cwd' do
    let(:capture) { fixture.fetch('deleted') }

    it 'keeps the callback cwd rejection enabled' do
      expect do
        target.ss_session(attempt, SudoChrootTarget::OWNER, 0, expected_cwd: '/tmp')
      end.to raise_error(RSpec::Expectations::ExpectationNotMetError, /New callback identity and usable cwd/)
    end
  end
end
