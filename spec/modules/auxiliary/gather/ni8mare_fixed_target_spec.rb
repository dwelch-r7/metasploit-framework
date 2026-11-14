require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/ni8mare/target_context'

RSpec.describe 'Genuine n8n guarded member file and session extraction', acceptance: true, order: :defined do
  include_context 'n8n functional target'

  def blocked(options, reuse: false)
    output, files = call_owner({ 'HttpTrace' => true, 'HttpTraceColors' => '/' }.merge(options), reuse: reuse)
    expect(output).to match(%r{HTTP/1\.[01] 500\b})
    expect(output).to match(/Auxiliary (?:aborted due to failure|failed): unexpected-reply/)
    expect(output).not_to include('JWT ticket as', 'Results saved to:', 'Database saved to:', 'Config file saved to:')
    expect(files).to eq([])
    expect(reports.values).to all(eq([]))
    idle
  end

  it 'rejects JSON-confusion file reads at the genuine public guard twice' do
    2.times { |iteration| blocked({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => @native.fetch('files').fetch('binary').fetch('path') }, reuse: iteration.positive?) }
  end

  it 'rejects database extraction and produces no owner token twice' do
    2.times { |iteration| blocked({ 'ACTION' => 'EXTRACT_SESSION', 'TARGET_EMAIL' => @fixture.fetch('email') }, reuse: iteration.positive?) }
  end

  it 'rejects incorrect member credentials without loot twice' do
    2.times do |iteration|
      output, files = call_owner({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => @native.fetch('files').fetch('text').fetch('path'), 'PASSWORD' => 'module-target-incorrect' }, reuse: iteration.positive?)
      expect(output).to match(/Auxiliary (?:aborted due to failure|failed): no-access/)
      expect(files).to eq([])
      expect(reports.values).to all(eq([]))
    end
  end

  it 'rejects a missing file through the same public type guard twice' do
    2.times { |iteration| blocked({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => @native.fetch('missing_path') }, reuse: iteration.positive?) }
  end

  it 'restores state across repeated file-to-session action transitions' do
    2.times do |iteration|
      blocked({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => @native.fetch('files').fetch('text').fetch('path') }, reuse: iteration.positive?)
      blocked({ 'ACTION' => 'EXTRACT_SESSION', 'TARGET_EMAIL' => @fixture.fetch('email') }, reuse: true)
      record('mode-transition-proofs.jsonl', iteration: iteration, registry_preserved: true)
    end
  end

  it 'handles the native-proven refused port without loot twice' do
    2.times do |iteration|
      output, files = call_owner({ 'ACTION' => 'EXTRACT_SESSION', 'TARGET_EMAIL' => @fixture.fetch('email'), 'RPORT' => 1 }, reuse: iteration.positive?)
      expect(output).to match(/Auxiliary (?:aborted due to failure|failed): (?:unreachable|no-access)/)
      expect(files).to eq([])
      expect(reports.values).to all(eq([]))
    end
  end
end
