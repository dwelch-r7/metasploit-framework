require 'acceptance_spec_helper'
require 'csv'
require 'rbconfig'

RSpec.describe 'Native Elasticsearch enumeration targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/elasticsearch/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-elasticsearch-before.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-elasticsearch-command.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @profiles = JSON.parse(stdout).fetch('profiles')
    @documents = JSON.parse(File.read('test/module_targets/elasticsearch/documents.json'))
  end

  %w[open secured].each do |service|
    it "gathers actual #{service} metadata and exact bounded CSV data twice" do
      2.times do
        output = enumerate(service)
        verify_metadata(output, service)
        expect(record_loot(output)).to match_array(expected_records(service, 5))
        expect(output).not_to include('module_target_empty data stored to')
        expect(output).to include('module_target_reader', 'module-target-reader@example.test') if service == 'secured'
      end
    end
  end

  it 'gathers permitted data with a native read/monitor role while reporting refused user enumeration' do
    output = enumerate('secured', 'USERNAME' => 'module_target_reader', 'PASSWORD' => 'module-target-reader-password')
    verify_metadata(output, 'secured')
    expect(record_loot(output)).to match_array(expected_records('secured', 5))
    expect(output).to include('Unable to pull user data')
    expect(output).not_to include('User Information')
  end

  [1, 10].each do |limit|
    it "bounds downloaded rows to #{limit} against seven actual records" do
      output = enumerate('open', 'DOWNLOADROWS' => limit)
      expect(record_loot(output)).to match_array(expected_records('open', limit))
    end
  end

  it 'handles a zero-row selection without dereferencing absent search hits or inventing CSV data' do
    output = enumerate('open', 'DOWNLOADROWS' => 0)
    expect(output).not_to include('data stored to')
    expect(output).to match(/Cluster Information|DOWNLOADROWS.*(?:positive|greater than|at least)/i)
  end

  {
    'missing credentials' => { 'USERNAME' => nil, 'PASSWORD' => nil },
    'wrong password' => { 'PASSWORD' => 'wrong-password' },
    'blank password' => { 'PASSWORD' => nil }
  }.each do |label, options|
    it "refuses the native authenticated target with #{label}" do
      output = enumerate('secured', options)
      expect(output).to include('Credentials required, or incorrect')
      expect(output).not_to include('data stored to', 'Cluster Information')
    end
  end

  it 'reports an actual authenticated permission denial without a parser exception' do
    output = enumerate('secured', 'USERNAME' => 'module_target_denied', 'PASSWORD' => 'module-target-denied-password')
    expect(output).to match(/permission|denied|privilege|Credentials required/i)
    expect(output).not_to include('data stored to')
  end

  it 'does not identify unrelated real HTTP or produce Elasticsearch loot' do
    output = enumerate('unrelated')
    expect(output).to match(/not Elasticsearch|cluster name not found|Unable to parse JSON/i)
    expect(output).not_to include('data stored to', 'Elastic Information', 'Cluster Information')
  end

  def enumerate(service, options = {})
    credentials = service == 'secured' ? { 'USERNAME' => 'elastic', 'PASSWORD' => 'module-target-password' } : { 'USERNAME' => nil, 'PASSWORD' => nil }
    # Native admin may enumerate security-owned indices whose direct reads are
    # refused by Elasticsearch. Expected denial diagnostics are retained.
    run_target_module('auxiliary/gather/elasticsearch_enum', service, { 'SSL' => false }.merge(credentials).merge(options), allow_errors: true)
  end

  def verify_metadata(output, service)
    profile = @profiles.fetch(service)
    version = profile.fetch('version')
    expect(output).to include(version.fetch('name'), version.fetch('cluster_name'), version.fetch('version').fetch('number'), version.fetch('version').fetch('lucene_version'))
    expect(output).to include('Node Information', 'Cluster Information', 'module_target_records', 'module_target_empty')
    profile.fetch('nodes').each { |node| expect(output).to include(node.fetch('name'), node.fetch('ip'), node.fetch('http')) }
  end

  def record_loot(output)
    paths = output.scan(/module_target_records data stored to ([^\r\n]+)/).flatten.map(&:strip)
    expect(paths.size).to eq(1), output
    expect(File.expand_path(paths.first)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    table = CSV.parse(File.binread(paths.first).force_encoding(Encoding::UTF_8), headers: true)
    expect(table.headers).to eq(@documents.first.keys)
    table.map(&:to_h)
  end

  def expected_records(service, limit)
    @profiles.fetch(service).fetch('samples').fetch(limit.to_s).map { |document| document.transform_values(&:to_s) }
  end
end
