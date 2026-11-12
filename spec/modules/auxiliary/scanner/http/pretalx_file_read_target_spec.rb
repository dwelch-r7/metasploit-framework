require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/pretalx/control'

RSpec.describe 'Genuine Pretalx schedule file collection', acceptance: true, order: :defined do
  include_context 'pretalx reporting target'

  it 'does not invent a hidden production version on two checks' do
    2.times do
      output = owner({}, action: 'check')
      expect(output).to include('Pretalx detected, failed to verify version')
      expect(reports.fetch('loot')).to eq([])
    end
  end

  it 'collects exact file bytes or honors the patched AutoCheck decision twice' do
    collect_twice({}, exposed: vulnerable?)
  end

  it 'uses actual patched file protection with ForceExploit twice' do
    collect_twice({ 'ForceExploit' => true })
  end

  it 'uses actual file protection with AutoCheck disabled twice' do
    collect_twice({ 'AutoCheck' => false })
  end

  it 'preserves a path containing spaces twice' do
    collect_twice({ 'AutoCheck' => false, 'FILEPATH' => '/data/proof/space name.txt' }, content: "Pretalx space file\n")
  end

  it 'handles missing and empty files without an exception or false file contents' do
    %w[missing.txt empty.txt missing.txt empty.txt].each do |name|
      output = owner({ 'AutoCheck' => false, 'FILEPATH' => "/data/proof/#{name}" })
      expect(output).not_to include('Stored results in')
      expect(reports).to eq('loot' => [], 'vulns' => [])
    end
  end

  it 'handles invalid credentials on two public checks' do
    2.times do
      output = owner({ 'PASSWORD' => 'wrong-password' }, action: 'check')
      expect(output).to match(/credentials|Failed to get session cookie/)
      expect(reports).to eq('loot' => [], 'vulns' => [])
    end
  end

  it 'refuses insufficient organizer permissions twice without false loot' do
    2.times do
      owner({ 'EMAIL' => 'speaker@example.invalid', 'AutoCheck' => false })
      expect(reports).to eq('loot' => [], 'vulns' => [])
    end
  end
end
