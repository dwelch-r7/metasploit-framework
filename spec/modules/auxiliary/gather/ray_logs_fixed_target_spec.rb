require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/ray_logs_enum/acceptance'

RSpec.describe 'Genuine fixed Ray log enumeration owner', acceptance: true do
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

  it 'reports the genuine fixed version safe twice' do
    2.times do
      output = run_target_module(owner, 'ray', {}, action: 'check')
      expect(output).to include('The target is not exploitable.', 'Ray version 2.57.0 is not vulnerable')
    end
  end

  it 'refuses automatic execution against existing outside files twice without loot' do
    2.times do
      before = logs_loot_files
      output = run_target_module(owner, 'ray', { 'FILE_PATH' => @fixture.fetch('patterns').fetch('all').fetch('glob') }, allow_errors: true)
      expect(output).to include('Ray version 2.57.0 is not vulnerable')
      expect(output).not_to include('Filesystem entries found', 'Loot stored in:')
      expect(logs_loot_files).to eq(before)
    end
  end

  it 'cannot enumerate real outside fixtures with AutoCheck disabled on repeat' do
    2.times do
      %w[all quoted percent wildcard literal_question empty missing check].each do |name|
        before = logs_loot_files
        output = run_target_module(owner, 'ray', {
          'NODE_ID' => @fixture.fetch('node_id'),
          'FILE_PATH' => @fixture.fetch('patterns').fetch(name).fetch('glob'),
          'AutoCheck' => false
        }, allow_errors: true)
        expect(output).to include('Failed to enumerate filesystem entries')
        expect(output).not_to include('Filesystem entries found', 'Loot stored in:')
        expect(logs_loot_files).to eq(before)
      end
    end
  end

  it 'still enumerates an ordinary owned log into exact new loot twice' do
    2.times { verify_enumeration(owner, 'ordinary', 'NODE_ID' => " #{@fixture.fetch('node_id')} ", 'AutoCheck' => false) }
  end

  it 'rejects an absolute path to an existing outside file twice without loot' do
    2.times do
      before = logs_loot_files
      output = run_target_module(owner, 'ray', {
        'NODE_ID' => @fixture.fetch('node_id'),
        'FILE_PATH' => File.join(@fixture.fetch('root'), 'outside', 'plain.txt'),
        'AutoCheck' => false
      }, allow_errors: true)
      expect(output).to include('Failed to enumerate filesystem entries')
      expect(output).not_to include('Filesystem entries found', 'Loot stored in:')
      expect(logs_loot_files).to eq(before)
    end
  end

  it 'rejects an unknown node for an existing ordinary log without loot' do
    before = logs_loot_files
    output = run_target_module(owner, 'ray', {
      'NODE_ID' => '0' * 56, 'FILE_PATH' => File.basename(@fixture.fetch('log_file')), 'AutoCheck' => false
    }, allow_errors: true)
    expect(output).to include('Failed to enumerate filesystem entries')
    expect(logs_loot_files).to eq(before)
  end

  it 'returns unknown on unrelated Apache content' do
    output = run_target_module(owner, 'unrelated', {}, action: 'check', allow_errors: true)
    expect(output).to include('Cannot reliably check exploitability.', 'No response or unexpected status from Ray API')
  end
end
