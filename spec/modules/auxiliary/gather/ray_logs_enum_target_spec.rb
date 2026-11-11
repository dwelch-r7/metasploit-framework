require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/ray_logs_enum/acceptance'

RSpec.describe 'Genuine Ray log enumeration owner', acceptance: true do
  include_context 'module target'
  include Acceptance::RayLogEnumeration

  owner = 'auxiliary/gather/ray_dashboard_logs_api_path_traversal'

  before(:all) do
    logs_phase('before')
    @fixture = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'owner-fixtures.json')))
  end

  after(:all) do
    logs_phase('after') if @fixture
  end

  it 'discovers the genuine node and checks traversal twice' do
    2.times do
      output = run_target_module(owner, 'ray', {}, action: 'check')
      expect(output).to include('The target is vulnerable.', 'Ray 2.56.0 - path traversal via /api/v0/logs confirmed', @fixture.fetch('node_id'))
    end
  end

  it 'enumerates an outside directory and writes exact new loot twice' do
    2.times { verify_enumeration(owner, 'all') }
  end

  it 'uses an explicit whitespace-trimmed node and quoted UTF8 path twice without AutoCheck' do
    2.times { verify_enumeration(owner, 'quoted', 'NODE_ID' => " #{@fixture.fetch('node_id')} ", 'AutoCheck' => false) }
  end

  it 'preserves literal percent escapes in path names twice' do
    2.times { verify_enumeration(owner, 'percent') }
  end

  it 'distinguishes wildcard and literal question marks on repeat' do
    2.times do
      verify_enumeration(owner, 'wildcard', 'NODE_ID' => @fixture.fetch('node_id'), 'AutoCheck' => false)
      verify_enumeration(owner, 'literal_question', 'NODE_ID' => @fixture.fetch('node_id'), 'AutoCheck' => false)
    end
  end

  it 'enumerates a real empty file twice' do
    2.times { verify_enumeration(owner, 'empty') }
  end

  it 'enumerates an ordinary owned log filename twice' do
    2.times { verify_enumeration(owner, 'ordinary') }
  end

  it 'handles the native empty result map without inventing paths or loot twice' do
    2.times do
      before = logs_loot_files
      output = run_target_module(owner, 'ray', { 'FILE_PATH' => @fixture.fetch('patterns').fetch('missing').fetch('glob'), 'AutoCheck' => false }, allow_errors: true)
      expect(output).to include('Failed to enumerate filesystem entries')
      expect(output).not_to include('Loot stored in:')
      expect(logs_loot_files).to eq(before)
    end
  end

  it 'reports an unknown node without producing loot' do
    before = logs_loot_files
    output = run_target_module(owner, 'ray', { 'NODE_ID' => '0' * 56, 'FILE_PATH' => '*', 'AutoCheck' => false }, allow_errors: true)
    expect(output).to include('Failed to enumerate filesystem entries')
    expect(logs_loot_files).to eq(before)
  end

  it 'returns unknown on unrelated Apache content' do
    output = run_target_module(owner, 'unrelated', {}, action: 'check', allow_errors: true)
    expect(output).to include('Cannot reliably check exploitability.', 'No response or unexpected status from Ray API')
  end

  it 'honors automatic refusal on unrelated content without loot twice' do
    2.times do
      before = logs_loot_files
      output = run_target_module(owner, 'unrelated', { 'FILE_PATH' => @fixture.fetch('patterns').fetch('all').fetch('glob') }, allow_errors: true)
      expect(output).to include('Cannot reliably check exploitability.')
      expect(logs_loot_files).to eq(before)
    end
  end
end
