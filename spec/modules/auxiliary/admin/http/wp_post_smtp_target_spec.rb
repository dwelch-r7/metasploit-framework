require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/post_smtp/acceptance'

RSpec.describe 'Native POST SMTP account reset disclosure', acceptance: true, order: :defined do
  include_context 'native POST SMTP target'

  mode = PostSmtpProfiles.fetch.fetch('mode')
  if mode == 'vulnerable'
    it 'identifies the affected release twice without changing account or plugin state' do
      2.times { expect(ps_unchanged(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'retrieves two fresh reset URLs and their exact real email logs with AutoCheck enabled' do
      2.times { ps_success }
    end

    it 'retrieves two fresh reset URLs with AutoCheck disabled' do
      2.times { ps_success('AutoCheck' => false) }
    end

    it 'rejects a missing user before registering a device or sending reset email' do
      expect(ps_unchanged({ 'USERNAME' => 'module_target_missing' })).to include('not found on this wordpress install')
    end
  elsif mode == 'fixed'
    it 'identifies the fixed release twice without changing account or plugin state' do
      2.times { expect(ps_unchanged(action: 'check')).to include('not exploitable') }
    end

    it 'refuses the fixed target twice through AutoCheck' do
      2.times { expect(ps_unchanged).to include('not-vulnerable:') }
    end

    it 'rejects the real unsuccessful registration before resetting the password on either run' do
      2.times { expect(ps_unchanged({ 'AutoCheck' => false })).to include('no-access: POST SMTP rejected mobile-device registration;') }
    end
  elsif mode == 'no_logs'
    it 'reports missing logs on both runs after real SMTP delivery without a Ruby error' do
      2.times do
        output = ps_owner
        expect(output).not_to include('Reset URL:', 'Full text of log saved to:')
        expect(output).to include('not-found: No email logs are available; check POST SMTP email logging and delivery')
        @ps_mail_count += 1
        expect(ps_mailbox(@ps_mail_count).length).to eq(@ps_mail_count)
        expect(ps_state('logging-disabled-after-owner').fetch('logs')).to eq([])
      ensure
        ps_restore
      end
    end
  else
    it 'rejects a missing plugin or unrelated service on both checks' do
      2.times { expect(ps_unchanged(action: 'check')).not_to include('appears to be vulnerable') }
    end

    it 'refuses execution on both automatic checks' do
      2.times { expect(ps_unchanged).to include('Auxiliary aborted due to failure:') }
    end
  end
end
