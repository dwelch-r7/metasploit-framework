require 'spec_helper'
require 'json'

RSpec.describe Rex::Parser::GPP do
  let(:capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'rex/parser/group_policy_preferences/native.json'))) }

  it 'preserves native ASCII password bytes and the String return type' do
    item = capture.fetch('files').fetch('ascii')
    result = described_class.decrypt(item.fetch('cpassword'))

    expect(result).to be_a(String)
    expect(result.bytes).to eq(item.fetch('password').bytes)
  end

  it 'decodes the native non-ASCII UTF-16LE password correctly' do
    item = capture.fetch('files').fetch('unicode')

    expect(described_class.decrypt(item.fetch('cpassword'))).to eq(item.fetch('password'))
  end

  it 'preserves the native parsed username and Unicode password' do
    item = capture.fetch('files').fetch('unicode')
    result = described_class.parse(item.fetch('xml')).first

    expect(result.values_at(:USER, :PASS)).to eq(item.values_at('username', 'password'))
  end

  it 'keeps ordinary native ASCII table information' do
    item = capture.fetch('files').fetch('ascii')
    table = described_class.create_tables(described_class.parse(item.fetch('xml')), 'Groups.xml').first.to_s

    expect(table).to include(item.fetch('username'), item.fetch('password'))
  end

  it 'prints the actual parsed native data source name' do
    item = capture.fetch('files').fetch('datasource')
    table = described_class.create_tables(described_class.parse(item.fetch('xml')), 'DataSources.xml').first.to_s

    expect(table).to match(/DATASOURCE\s+ModuleTargetDSN/)
  end

  it 'retains the legacy DSN key for callers constructing their own results' do
    table = described_class.create_tables([{ USER: 'policy_user', PASS: 'public-password', DSN: 'LegacyDSN' }], 'DataSources.xml').first.to_s

    expect(table).to match(/DATASOURCE\s+LegacyDSN/)
  end

  it 'decodes an independently encrypted derived UTF-16 surrogate pair' do
    item = capture.fetch('derived').fetch('astral')

    expect(described_class.decrypt(item.fetch('cpassword'))).to eq(item.fetch('expected'))
  end

  it 'keeps an independently encrypted empty password as a String' do
    item = capture.fetch('derived').fetch('empty')

    expect(described_class.decrypt(item.fetch('cpassword'))).to eq('')
  end

  it 'returns the existing empty failure sentinel for invalid derived UTF-16' do
    item = capture.fetch('derived').fetch('invalid_utf16')

    expect(described_class.decrypt(item.fetch('cpassword'))).to eq('')
  end
end
