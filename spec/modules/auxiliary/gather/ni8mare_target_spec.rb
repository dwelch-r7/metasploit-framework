require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/ni8mare/target_context'

RSpec.describe 'Genuine n8n member file and owner session extraction', acceptance: true, order: :defined do
  include_context 'n8n functional target'

  it('collects exact binary bytes twice') { collect_file('binary') }
  it('collects exact plain text twice') { collect_file('text') }
  it('collects an actual empty file twice') { collect_file('empty') }
  it('collects exact Unicode content twice') { collect_file('unicode') }
  it('collects a file across the 64KiB boundary twice') { collect_file('large') }
  it('handles a filename containing spaces and Unicode twice') { collect_file('filename') }

  it('authenticates extracted ordinary-hash owner tickets twice') { session_extraction('ordinary') }
  it('authenticates extracted plus-hash owner tickets twice') { session_extraction('plus') }
  it('authenticates extracted slash-hash owner tickets twice') { session_extraction('slash') }

  it 'rejects incorrect member credentials without loot twice' do
    2.times do |iteration|
      output, files = call_owner({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => @native.fetch('files').fetch('text').fetch('path'), 'PASSWORD' => 'module-target-incorrect' }, reuse: iteration.positive?)
      expect(output).to match(/Auxiliary (?:aborted due to failure|failed): no-access/)
      expect(files).to eq([])
      expect(reports.values).to all(eq([]))
    end
  end

  it 'rejects an absent target user while retaining only genuine database loot twice' do
    2.times do |iteration|
      output, files = call_owner({ 'ACTION' => 'EXTRACT_SESSION', 'TARGET_EMAIL' => 'module.absent@example.test' }, reuse: iteration.positive?)
      expect(output).to match(/Auxiliary (?:aborted due to failure|failed): not-found/)
      expect(files.length).to eq(1)
      expect(File.binread(files.fetch(0), 16)).to eq("SQLite format 3\0")
      expect(output).not_to include('JWT ticket as', 'Config file saved to:')
      expect(reports.fetch('credentials')).to eq([])
      idle
    end
  end

  it 'rejects a native-proven missing file and restores workflow state twice' do
    rejected_file(@native.fetch('missing_path'))
  end

  it 'rejects a native-proven inaccessible file and restores workflow state twice' do
    rejected_file(@native.fetch('denied_path'))
  end

  it 'handles the native-proven refused port without loot twice' do
    2.times do |iteration|
      output, files = call_owner({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => @native.fetch('files').fetch('text').fetch('path'), 'RPORT' => 1 }, reuse: iteration.positive?)
      expect(output).to match(/Auxiliary (?:aborted due to failure|failed): (?:unreachable|no-access)/)
      expect(files).to eq([])
      expect(reports.values).to all(eq([]))
    end
  end
end
