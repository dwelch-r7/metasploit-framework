require 'rspec'
require 'json'

RSpec.describe 'Jenkins command scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/jenkins_command') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/jenkins_command/responses.json'))).fetch('responses') }
  let(:host) { '192.0.2.54' }

  before do
    mod.datastore['RHOSTS'] = host
    mod.datastore['TARGETURI'] = '/jenkins/'
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:report_vulnerable)
  end

  describe '#fingerprint_os' do
    it 'extracts the modern native crumb and its real field name' do
      allow(mod).to receive(:send_request_cgi).and_return(response('modern_system_info'))

      expect(mod.fingerprint_os(host)).to include(crumb: 'a' * 64, crumb_name: 'Jenkins-Crumb')
    end

    it 'retains the empty Linux prefix from the actual OS property value' do
      allow(mod).to receive(:send_request_cgi).and_return(response('modern_system_info'))

      expect(mod.fingerprint_os(host)).to include(prefix: '')
    end

    it 'recognizes the genuine page identity when a proxy removes the version header' do
      captured = response('modern_system_info')
      captured.headers.delete('X-Jenkins')
      allow(mod).to receive(:send_request_cgi).and_return(captured)

      expect(mod.fingerprint_os(host)).to include(prefix: '')
    end

    it 'reads a Windows property from a derived row without selecting hidden controls' do
      captured = response('modern_system_info')
      captured.body = captured.body.sub(' Linux</span>', ' Windows Server 2022</span>')
      allow(mod).to receive(:send_request_cgi).and_return(captured)

      expect(mod.fingerprint_os(host)).to include(prefix: 'cmd.exe /c ')
    end

    it 'keeps the existing legacy crumb contract on an explicitly derived script variant' do
      captured = response('modern_system_info')
      captured.body = captured.body.sub(/data-crumb-header="[^"]+" data-crumb-value="[^"]+"/, '') + '<script>".crumb", "legacycrumb"</script>'
      allow(mod).to receive(:send_request_cgi).and_return(captured)

      expect(mod.fingerprint_os(host)).to include(crumb: 'legacycrumb', crumb_name: '.crumb')
    end

    it 'does not dereference an absent OS property' do
      captured = response('modern_system_info')
      captured.body = captured.body.gsub('os.name', 'module-target-missing-property')
      allow(mod).to receive(:send_request_cgi).and_return(captured)

      expect(mod.fingerprint_os(host)).to be_nil
    end

    it 'does not mutate the captured response body' do
      captured = response('modern_system_info')
      captured.body.freeze
      allow(mod).to receive(:send_request_cgi).and_return(captured)

      expect { mod.fingerprint_os(host) }.not_to raise_error
    end

    it 'handles a target that does not respond' do
      allow(mod).to receive(:send_request_cgi).and_return(nil)

      expect(mod.fingerprint_os(host)).to be_nil
    end
  end

  describe 'native target policy' do
    it 'identifies actual authorization refusal before attempting a command' do
      allow(mod).to receive(:send_request_cgi).and_return(response('secured'))

      mod.run_host(host)

      expect(mod).to have_received(:vprint_error).with(/requires authentication/)
    end

    it 'does not execute a POST on the actual unrelated HTTP response' do
      allow(mod).to receive(:send_request_cgi).and_return(response('unrelated'))

      mod.run_host(host)

      expect(mod).to have_received(:send_request_cgi).once
    end

    it 'does not identify an unrelated authorization error as a Jenkins login requirement' do
      captured = response('unrelated')
      captured.code = 403
      allow(mod).to receive(:send_request_cgi).and_return(captured)

      mod.run_host(host)

      expect(mod).not_to have_received(:vprint_error).with(/requires authentication/)
    end
  end

  describe 'captured command results' do
    %w[plain literal entities unicode].each do |name|
      it "preserves the actual #{name} output reported by Jenkins" do
        captured = captures.fetch("#{name}_envelope")
        expected = JSON.parse(captured.fetch('body')).fetch('stdout')
        mod.datastore['COMMAND'] = captured.fetch('command')
        stub_command_responses(name)

        mod.run_host(host)

        expect(mod).to have_received(:report_vulnerable).with(expected)
      end
    end

    it 'reports a successfully executed no-output command through the same result contract' do
      stub_command_responses('empty')

      mod.run_host(host)

      expect(mod).to have_received(:report_vulnerable).with('')
    end

    it 'does not present the native missing executable error as successful command output' do
      stub_command_responses('missing')

      mod.run_host(host)

      expect(mod).not_to have_received(:report_vulnerable)
    end

    it 'retains the native operation failure reason without a raw target backtrace' do
      stub_command_responses('missing')

      mod.run_host(host)

      expect(mod).to have_received(:vprint_error).with(/Command execution failed: Cannot run program .*No such file or directory/)
    end

    it 'retains stderr from a real nonzero process result' do
      stub_command_responses('stderr')
      expected = JSON.parse(captures.fetch('stderr_envelope').fetch('body')).fetch('stderr')

      mod.run_host(host)

      expect(mod).to have_received(:report_vulnerable).with(expected)
    end

    it 'carries the actual session cookie and matching modern crumb to the command POST' do
      requests = []
      allow(mod).to receive(:send_request_raw) do |options, *_arguments|
        requests << options if options['method'] == 'POST'
        options['method'] == 'POST' ? response('plain_envelope') : response('modern_system_info')
      end

      mod.run_host(host)

      expect(requests.first).to include(
        'cookie' => 'JSESSIONID.fixture=fixture-session;',
        'vars_post' => include('Jenkins-Crumb' => 'a' * 64)
      )
    end

    it 'preserves the configured command bytes and binary encoding tag' do
      command = captures.fetch('unicode_envelope').fetch('command')
      mod.datastore['COMMAND'] = command.b
      stub_command_responses('unicode')

      mod.run_host(host)

      expect([mod.datastore['COMMAND'].encoding, mod.datastore['COMMAND'].bytes]).to eq([Encoding::ASCII_8BIT, command.bytes])
    end

    it 'does not invent a command result from a malformed JSON response' do
      allow(mod).to receive(:send_request_cgi) do |options|
        options['method'] == 'POST' ? Rex::Proto::Http::Response.new(200).tap { |res| res.body = 'not JSON' } : response('modern_system_info')
      end

      mod.run_host(host)

      expect(mod).not_to have_received(:report_vulnerable)
    end

    it 'does not accept a JSON array as a command result' do
      allow(mod).to receive(:send_request_cgi) do |options|
        options['method'] == 'POST' ? Rex::Proto::Http::Response.new(200).tap { |res| res.body = '[]' } : response('modern_system_info')
      end

      mod.run_host(host)

      expect(mod).not_to have_received(:report_vulnerable)
    end

    it 'does not accept command streams without the native integer exit status' do
      captured = response('plain_envelope')
      parsed = captured.get_json_document
      parsed['exit_status'] = nil
      captured.body = parsed.to_json
      allow(mod).to receive(:send_request_cgi) { |options| options['method'] == 'POST' ? captured : response('modern_system_info') }

      mod.run_host(host)

      expect(mod).not_to have_received(:report_vulnerable)
    end

    it 'handles no response from the command request without raising' do
      allow(mod).to receive(:send_request_cgi) { |options| options['method'] == 'POST' ? nil : response('modern_system_info') }

      expect { mod.run_host(host) }.not_to raise_error
    end

    it 'does not accept an unexpected command-request HTTP status' do
      captured = response('plain_envelope')
      captured.code = 403
      allow(mod).to receive(:send_request_cgi) { |options| options['method'] == 'POST' ? captured : response('modern_system_info') }

      mod.run_host(host)

      expect(mod).not_to have_received(:report_vulnerable)
    end
  end

  def stub_command_responses(name)
    allow(mod).to receive(:send_request_cgi) do |options|
      if options['method'] != 'POST'
        response('modern_system_info')
      elsif options.fetch('uri').end_with?('/scriptText')
        response("#{name}_envelope")
      else
        response("#{name}_original")
      end
    end
  end

  def response(name)
    capture = captures.fetch(name)
    Rex::Proto::Http::Response.new(capture.fetch('code')).tap do |result|
      result.body = capture.fetch('body').dup
      capture.fetch('headers').each { |key, value| result.headers[key] = value }
    end
  end
end
