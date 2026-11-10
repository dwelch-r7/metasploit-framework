require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/prometheus/native'

RSpec.describe 'Genuine Prometheus API and Linux exporter targets' do
  include_context 'module target'

  before(:all) do
    @native_driver = PrometheusTarget.new(target_runtime)
    begin
      @native = @native_driver.prepare
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-prometheus.json'), JSON.pretty_generate(@native))
    ensure
      save_native_records
    end
  end

  after do
    save_native_records
  end

  %w[old modern secured empty].each do |service|
    it "collects exact native API configuration and targets twice on #{service}" do
      profile = @native.fetch('api').fetch(service)
      options = { 'TARGETURI' => PrometheusTarget::PREFIXES.fetch(service) }
      options.merge!('HttpUsername' => PrometheusTarget::USERNAME, 'HttpPassword' => PrometheusTarget::PASSWORD) if service == 'secured'
      2.times do
        before = loot_files
        output = gather('prometheus_api_gather', service, options)
        paths = loot_files - before
        yaml_path = output[/YAML config saved to (.+)$/, 1]&.strip
        targets_path = output[/JSON targets saved to (.+)$/, 1]&.strip
        aggregate_failures do
          expect(output).to include("Prometheus found, version: #{profile.dig('build', 'data', 'version')}")
          expect(output).to include("Config file: #{profile.dig('flags', 'data', 'config.file')}")
          expect(paths.length).to eq(2)
          expect(yaml_path).not_to be_nil, output
          expect(targets_path).not_to be_nil, output
          if yaml_path
            expect(paths).to include(yaml_path)
            expect(File.binread(yaml_path)).to eq(profile.dig('config', 'data', 'yaml'))
          end
          if targets_path
            expect(paths).to include(targets_path)
            target_data = JSON.parse(File.binread(targets_path))
            expect(PrometheusTarget.target_projection(target_data)).to eq(PrometheusTarget.target_projection(profile.fetch('targets')))
            expect(target_data.dig('data', 'activeTargets').all? { |target| target.fetch('health') == 'up' }).to be(true)
          end
          verify_credentials(output, profile.fetch('parsed_config')) unless service == 'empty'
          expect(output).not_to include('Credentials') if service == 'empty'
        end
      end
    end
  end

  [
    ['secured', {}, 'missing API credentials'],
    ['secured', { 'HttpUsername' => PrometheusTarget::USERNAME, 'HttpPassword' => 'incorrect-password' }, 'wrong API credentials'],
    ['discovery', {}, 'unrelated Apache API'],
    ['node', {}, 'an exporter rather than Prometheus API'],
    ['old', { 'TARGETURI' => '/missing-prefix/' }, 'wrong API prefix']
  ].each do |service, options, label|
    it "rejects #{label} without information loot" do
      before = loot_files
      output = gather('prometheus_api_gather', service, options, allow_errors: true)
      expect(output).to include('Unexpected response from server')
      expect(output).not_to include('YAML config saved', 'JSON targets saved')
      expect(loot_files).to eq(before)
    end
  end

  [
    ['node', 'node', {}],
    ['node_legacy', 'node_legacy', {}],
    ['node_auth', 'node_auth', { 'HttpUsername' => PrometheusTarget::USERNAME, 'HttpPassword' => PrometheusTarget::PASSWORD }],
    ['discovery', 'node', { 'TARGETURI' => '/node/' }]
  ].each do |service, native_service, options|
    it "reports genuine Linux information twice through #{service}" do
      2.times do
        before = loot_files
        output = gather('prometheus_node_exporter_gather', service, options)
        aggregate_failures do
          expect(output).to include(@native.fetch('nodes').fetch(native_service).fetch('hostname'))
          verify_node_information(output, @native.fetch('nodes').fetch(native_service).fetch('query'))
          expect(loot_files).to eq(before)
        end
      end
    end
  end

  it 'does not invent host information from a genuine metadata-only exporter' do
    before = loot_files
    output = gather('prometheus_node_exporter_gather', 'node_empty')
    expect(output).not_to include('Go Version:', 'OS Information', 'uname Information', 'File Systems', 'Network Interfaces', 'SELinux enabled:', 'Timezone:')
    expect(loot_files).to eq(before)
  end

  [
    ['node_auth', {}, 'missing exporter credentials', 'Unexpected response from server'],
    ['node_auth', { 'HttpUsername' => PrometheusTarget::USERNAME, 'HttpPassword' => 'incorrect-password' }, 'wrong exporter credentials', 'Unexpected response from server'],
    ['discovery', {}, 'unrelated Apache exporter', 'Prometheus Node Exporter not found'],
    ['discovery', { 'TARGETURI' => '/missing-prefix/' }, 'wrong exporter prefix', 'Unexpected response from server']
  ].each do |service, options, label, reason|
    it "rejects #{label} without host information or loot" do
      before = loot_files
      output = gather('prometheus_node_exporter_gather', service, options, allow_errors: true)
      expect(output).to include(reason)
      expect(output).not_to include('OS Information', 'uname Information', 'File Systems')
      expect(loot_files).to eq(before)
    end
  end

  def gather(name, service, options = {}, allow_errors: false)
    output = run_target_module("auxiliary/gather/#{name}", service, { 'SSL' => false }.merge(options), allow_errors: allow_errors)
    expect(output).not_to match(/Error running|Exception|undefined method|Unknown datastore option/)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/) unless allow_errors
    output
  end

  def verify_credentials(output, config)
    jobs = config.fetch('scrape_configs').to_h { |job| [job.fetch('job_name'), job] }
    dns = jobs.fetch('dns-file')
    discovery = dns.fetch('dns_sd_configs').first
    expect(output).to match(/^\s+dns-file\s+dns_sd_configs\s+#{Regexp.escape(discovery.fetch('names').first)}\s+#{discovery.fetch('port')}\s+#{Regexp.escape(dns.dig('basic_auth', 'username'))}\s+#{Regexp.escape(dns.dig('basic_auth', 'password_file'))}/)
    inline = jobs.fetch('dns-inline')
    expect(output).to include(inline.dig('basic_auth', 'password'))
    static = jobs.fetch('static-basic')
    expect(output).to match(/^\s+static-basic\s+.*#{Regexp.escape(static.dig('basic_auth', 'username'))}\s+#{Regexp.escape(static.dig('basic_auth', 'password_file'))}/)
    bearer = jobs.fetch('bearer-file').fetch('authorization')
    expect(output).to match(/^\s+bearer-file\s+authorization\s+#{Regexp.escape(bearer.fetch('type'))}\s+#{Regexp.escape(bearer.fetch('credentials_file'))}/)
    uri = URI(jobs.fetch('http-discovery').fetch('http_sd_configs').first.fetch('url'))
    expect(output).to match(/^\s+http-discovery\s+http_sd_configs\s+#{Regexp.escape(uri.host)}\s+#{uri.port}\s+#{Regexp.escape(uri.user)}\s+#{Regexp.escape(uri.password)}/)
  end

  def verify_node_information(output, samples)
    samples.each do |sample|
      labels = sample.fetch('metric')
      fields = case labels.fetch('__name__')
               when 'go_info'
                 expect(output).to include("Go Version: #{labels.fetch('version')}")
                 []
               when 'node_selinux_enabled'
                 expect(output).to include("SELinux enabled: #{sample.fetch('value').last}")
                 []
               when 'node_time_zone_offset_seconds'
                 expect(output).to include("Timezone: #{labels.fetch('time_zone')}")
                 []
               when 'node_uname_info'
                 %w[domainname machine release sysname version nodename]
               when 'node_os_info'
                 %w[id name version version_id version_codename pretty_name]
               when 'node_network_info'
                 %w[device address broadcast operstate]
               when 'node_filesystem_avail', 'node_filesystem_avail_bytes'
                 %w[device mountpoint fstype]
               else
                 raise "Unexpected native information metric: #{labels}"
               end
      fields.each { |field| expect(output).to include(labels.fetch(field)) unless labels.fetch(field).empty? }
    end
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end

  def save_native_records
    return unless @native_driver

    File.write(File.join(target_runtime.fetch('artifacts'), 'native-records.json'), JSON.pretty_generate(@native_driver.records))
  end
end
