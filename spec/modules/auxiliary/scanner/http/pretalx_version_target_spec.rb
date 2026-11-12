require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/pretalx/control'

RSpec.describe 'Genuine Pretalx disclosed development versions', acceptance: true, order: :defined do
  include_context 'pretalx reporting target'

  it 'checks the actual disclosed version twice' do
    2.times do
      output = owner({}, action: 'check')
      expect(output).to include(vulnerable? ? 'Detected vulnerable version 2.3.1' : 'Detected version 2.3.2 is not vulnerable')
      expect(reports.fetch('loot')).to eq([])
    end
  end

  it 'collects exact file bytes or honors the patched AutoCheck decision twice' do
    collect_twice({}, exposed: vulnerable?)
  end

  it 'handles invalid credentials on two public checks' do
    2.times do
      output = owner({ 'PASSWORD' => 'wrong-password' }, action: 'check')
      expect(output).to match(/credentials|Failed to get session cookie/)
      expect(reports).to eq('loot' => [], 'vulns' => [])
    end
  end
end
