require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native HTTP forward proxy targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/http_proxy/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-http-proxy.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-http-proxy-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(JSON.parse(stdout).fetch('requests').size).to eq(9)
    %w[open denied].each do |service|
      expect(target_exec(service, 'httpd', '-c', "Include conf/extra/#{service}.conf", '-M')).to include('proxy_http_module', 'proxy_connect_module')
    end
  end

  ['destination', 'http://destination:8080/'].each do |url|
    it "detects genuine GET forwarding for #{url} twice" do
      2.times do
        output = scan('open', url)
        expect(output).to include('Potentially open proxy [200][GET]', 'module-target-proxy-destination-proof')
      end
    end
  end

  it 'rejects a response with the wrong content pattern' do
    output = scan('open', 'http://destination:8080/', 'VALIDPATTERN' => 'module-target-absent-pattern')
    expect(output).to include('HTTP/1.1 200', 'module-target-proxy-destination-proof')
    expect(output).not_to include('Potentially open proxy')
  end

  it 'rejects a response with an unaccepted status code' do
    output = scan('open', 'http://destination:8080/', 'VALIDCODES' => '302')
    expect(output).to include('HTTP/1.1 200', 'module-target-proxy-destination-proof')
    expect(output).not_to include('Potentially open proxy')
  end

  %w[denied unrelated].each do |service|
    it "does not identify #{service} HTTP as open GET forwarding" do
      output = scan(service, 'http://destination:8080/')
      expect(output).to include(service == 'denied' ? 'HTTP/1.1 403' : 'module-target-http-marker')
      expect(output).not_to include('Potentially open proxy')
    end
  end

  { 'destination' => 443, 'https://destination:443/' => 443, 'https://destination:8443/' => 8443 }.each do |url, port|
    it "detects the genuine CONNECT tunnel for #{url} twice" do
      2.times do
        output = scan('open', url, 'VERIFYCONNECT' => true)
        expect(output).to include("CONNECT destination:#{port} HTTP/1.1", 'Potentially open proxy [200][CONNECT]')
      end
    end
  end

  %w[denied unrelated].each do |service|
    it "does not identify #{service} HTTP as a CONNECT tunnel" do
      output = scan(service, 'https://destination:443/', 'VERIFYCONNECT' => true)
      expect(output).to include(service == 'denied' ? 'HTTP/1.1 403' : 'HTTP/1.1 405')
      expect(output).not_to include('Potentially open proxy')
    end
  end

  it 'rejects a permitted CONNECT port without a listening destination' do
    output = scan('open', 'https://destination:8444/', 'VERIFYCONNECT' => true)
    expect(output).to include('HTTP/1.1 503')
    expect(output).not_to include('Potentially open proxy')
  end

  def scan(service, url, options = {})
    defaults = {
      'CHECKURL' => url, 'VALIDCODES' => '200', 'VALIDPATTERN' => 'module-target-proxy-destination-proof',
      'VERIFYCONNECT' => false, 'MULTIPORTS' => false, 'SSL' => false, 'HttpTrace' => true, 'THREADS' => 1
    }
    run_target_module('auxiliary/scanner/http/open_proxy', service, defaults.merge(options), allow_errors: true)
  end
end
