require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/piwigo/acceptance'

RSpec.describe 'Native Piwigo credential disclosure', acceptance: true, order: :defined do
  include_context 'native Piwigo target'

  mode = PiwigoProfiles.fetch.fetch('mode')
  if mode == 'affected'
    it 'identifies the affected release twice without saving credentials' do
      2.times { expect(pw_refusal(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'persists exact native hashes twice with AutoCheck enabled' do
      2.times { pw_success }
    end

    it 'persists the complete delimiter and Unicode collection twice with AutoCheck disabled' do
      2.times { pw_success('AutoCheck' => false) }
    end

    it 'rejects the wrong password twice without saving credentials' do
      2.times { expect(pw_refusal({ 'PASSWORD' => 'module-target-wrong-password' })).to include('no-access:') }
    end

    it 'rejects a valid nonadministrator twice without saving credentials' do
      2.times { expect(pw_refusal({ 'USERNAME' => 'module_reader' })).to match(/Target is NOT vulnerable|Auxiliary aborted due to failure:/) }
    end

    it 'refuses a nonexistent base path through AutoCheck' do
      expect(pw_refusal({ 'TARGETURI' => "#{pw_prefix}/module-target-missing/" })).to include('Auxiliary aborted due to failure:')
    end

    it 'does not save credentials when a missing path bypasses AutoCheck' do
      expect(pw_refusal({ 'TARGETURI' => "#{pw_prefix}/module-target-missing/", 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:')
    end
  elsif mode == 'empty'
    it 'identifies the release through the ordinary login page when the empty index omits it' do
      2.times { expect(pw_refusal(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'persists exact native hashes twice with AutoCheck enabled' do
      2.times { pw_success }
    end

    it 'persists exact native hashes twice when the operator disables AutoCheck' do
      2.times { pw_success('AutoCheck' => false) }
    end

    it 'rejects the wrong password even when AutoCheck is disabled' do
      expect(pw_refusal({ 'PASSWORD' => 'module-target-wrong-password', 'AutoCheck' => false })).to include('no-access:')
    end
  elsif mode == 'fixed'
    it 'identifies the fixed release twice without saving credentials' do
      2.times { expect(pw_refusal(action: 'check')).to match(/not exploitable/i) }
    end

    it 'refuses the fixed target twice through AutoCheck' do
      2.times { expect(pw_refusal).to include('not-vulnerable:') }
    end

    it 'saves no credential when forced past the fixed version check' do
      2.times { expect(pw_refusal({ 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:') }
    end
  else
    it 'does not identify the unrelated service as affected on either check' do
      2.times { expect(pw_refusal(action: 'check')).not_to include('appears to be vulnerable') }
    end

    it 'refuses the unrelated service with AutoCheck enabled and disabled' do
      expect(pw_refusal).to include('Auxiliary aborted due to failure:')
      expect(pw_refusal({ 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:')
    end
  end
end
