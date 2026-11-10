require 'spec_helper'
require 'rex/text'
require 'yaml'

RSpec.describe Msf::Auxiliary::Prometheus do
  subject(:auxiliary) { Class.new { include Msf::Auxiliary::Prometheus }.new }

  def capture(name)
    File.binread(File.join(__dir__, '../../../../file_fixtures/prometheus', name))
  end

  context 'with captured native Prometheus configurations' do
    before do
      allow(auxiliary).to receive(:credential_data).and_return({})
      allow(auxiliary).to receive(:create_credential_and_login)
      allow(auxiliary).to receive(:print_good)
    end

    %w[old modern].each do |version|
      context "with the #{version} API" do
        let(:config) { YAML.safe_load(capture("#{version}-api-config.yml")) }

        it 'retains the configured DNS port' do
          expect(auxiliary).to receive(:create_credential_and_login).with(hash_including(address: 'node_auth', port: 9100, username: 'metrics-user', private_data: '/etc/prometheus/fixtures/basic-password'))
          auxiliary.prometheus_config_eater(config)
        end

        it 'reports the static credential file reference' do
          expect(auxiliary).to receive(:print_good).with(%r{static-basic\s+static_configs\s+node_auth\s+9100\s+metrics-user\s+/etc/prometheus/fixtures/basic-password\s+Password file})
          auxiliary.prometheus_config_eater(config)
        end
      end
    end

    it 'does not report a static password file as an actual password' do
      config = YAML.safe_load(capture('old-api-config.yml'))
      config['scrape_configs'].select! { |job| job['job_name'] == 'static-basic' }
      expect(auxiliary).not_to receive(:create_credential_and_login)
      auxiliary.prometheus_config_eater(config)
    end

    # These substitute authentication fields to exercise the helper contract;
    # the native static-file capture does not expose an actual password.
    it 'labels a redaction marker without reporting a usable password' do
      config = YAML.safe_load(capture('old-api-config.yml'))
      config['scrape_configs'].select! { |job| job['job_name'] == 'static-basic' }
      config['scrape_configs'].first['basic_auth'] = { 'username' => 'metrics-user', 'password' => '<secret>' }
      expect(auxiliary).not_to receive(:create_credential_and_login)
      expect(auxiliary).to receive(:print_good).with(/static-basic\s+static_configs\s+node_auth\s+9100\s+metrics-user\s+<secret>\s+Redacted password/)
      auxiliary.prometheus_config_eater(config)
    end

    it 'reports an unredacted static password with its endpoint' do
      config = YAML.safe_load(capture('old-api-config.yml'))
      config['scrape_configs'].select! { |job| job['job_name'] == 'static-basic' }
      config['scrape_configs'].first['basic_auth'] = { 'username' => 'metrics-user', 'password' => 'public-example-password' }
      expect(auxiliary).to receive(:create_credential_and_login).with({ port: 9100, address: 'node_auth', username: 'metrics-user', private_data: 'public-example-password', service_name: 'http' })
      auxiliary.prometheus_config_eater(config)
    end
  end

  %w[node node_legacy].each do |service|
    it "decodes the actual quoted filesystem label from #{service}" do
      result = auxiliary.process_results_page(capture("#{service}-quoted-filesystem.txt"))
      expect(result.first.values.first.fetch('labels').fetch('mountpoint')).to eq('/data/metrics,"quote"')
    end
  end

  # Derived from the official text-format escaping example, rather than a
  # claim that the native exporter produced every supported escape sequence.
  it 'decodes the three documented label escapes without recursive decoding' do
    sample = <<~'METRICS'
      sample{path="C:\\DIR\\FILE.TXT",error="Cannot find file:\n\"FILE.TXT\"",literal="\\n"} 1
    METRICS
    result = auxiliary.process_results_page(sample)
    expect(result).to eq([{ 'sample' => { 'value' => '1', 'labels' => { 'path' => 'C:\\DIR\\FILE.TXT', 'error' => "Cannot find file:\n\"FILE.TXT\"", 'literal' => '\\n' } } }])
  end
end
