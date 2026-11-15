require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/bookingpress/acceptance'

RSpec.describe 'Native BookingPress credential gathering', acceptance: true, order: :defined do
  include_context 'native BookingPress target'

  mode = BookingpressProfiles.fetch.fetch('mode')
  if mode == 'affected'
    it 'proves injection on both public checks without saving credentials' do
      2.times { expect(bp_refusal(action: 'check')).to match(/The target is vulnerable/i) }
    end

    it 'saves every native user hash twice with AutoCheck enabled' do
      2.times { bp_success }
    end

    it 'saves every native user hash twice when AutoCheck is disabled' do
      2.times { bp_success('AutoCheck' => false) }
    end

    it 'rejects a page without a public booking nonce through check and AutoCheck' do
      path = { 'TARGETURI' => "#{bp_prefix}/module-target-missing/" }
      expect(bp_refusal(path, action: 'check')).to match(/cannot reliably check exploitability/i)
      expect(bp_refusal(path)).to include('Auxiliary aborted due to failure:')
    end

    it 'rejects a page without a nonce when AutoCheck is disabled' do
      expect(bp_refusal({ 'TARGETURI' => "#{bp_prefix}/module-target-missing/", 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:')
    end

    it 'does not identify a real PostgreSQL endpoint as vulnerable' do
      expect(bp_refusal(action: 'check', service: 'reporting_db')).to match(/cannot reliably check exploitability/i)
    end
  elsif mode == 'fixed'
    it 'returns a valid nonvulnerable result on both checks' do
      2.times { expect(bp_refusal(action: 'check')).to match(/not exploitable/i) }
    end

    it 'refuses both runs through AutoCheck without saving credentials' do
      2.times { expect(bp_refusal).to include('not-vulnerable:') }
    end

    it 'handles the fixed response when AutoCheck is disabled' do
      2.times { expect(bp_refusal({ 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:') }
    end
  else
    it 'does not identify the absent or unrelated target as vulnerable' do
      2.times { expect(bp_refusal(action: 'check')).to match(/cannot reliably check exploitability/i) }
    end

    it 'saves no credential with AutoCheck enabled or disabled' do
      expect(bp_refusal).to include('Auxiliary aborted due to failure:')
      expect(bp_refusal({ 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:')
    end
  end
end
