require 'acceptance_spec_helper'
require 'rbconfig'
require 'net/http'

RSpec.describe 'Native Consul execution targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/consul_exec/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-consul-exec.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-consul-exec-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
  end

  {
    'service' => 'exploit/multi/misc/consul_service_exec',
    'rexec' => 'exploit/multi/misc/consul_rexec_exec'
  }.each do |feature, fullname|
    it "checks the actual enabled #{feature} feature" do
      output = invoke(fullname, 'open', action: 'check')
      expect(output).to include('The target is vulnerable.')
    end

    it "checks the actual disabled #{feature} feature" do
      output = invoke(fullname, 'disabled', action: 'check')
      expect(output).to include('The target is not exploitable.')
    end

    it "checks #{feature} with an accepted ACL token" do
      output = invoke(fullname, 'secured', { 'ACL_TOKEN' => management_token }, action: 'check')
      expect(output).to include('The target is vulnerable.')
    end

    it "does not confirm #{feature} with a rejected ACL token" do
      output = invoke(fullname, 'secured', { 'ACL_TOKEN' => wrong_token }, action: 'check', allow_errors: true)
      expect(output).to include('Cannot reliably check exploitability.')
      expect(output).not_to include('The target is vulnerable.')
    end

    { 'open' => 'printf', 'secured' => 'wget' }.each do |service, flavor|
      it "executes #{feature} through #{flavor} twice on #{service} and restores state" do
        2.times do |index|
          path = "/tmp/module-target-#{feature}-#{service}-#{index}"
          before = snapshot(service)
          files = tmp_paths(service)
          target_exec(service, 'test', '!', '-e', path)
          begin
            output = invoke(fullname, service, delivery_options(feature, service, flavor, path), command_timeout: 100)
            expect(output).not_to match(/Exploit failed|Exploit aborted/)
            expect(target_exec(service, 'stat', '-c', '%u', path).strip).to eq(@native.fetch('profiles').fetch(service).fetch('uid'))
            target_exec(service, 'rm', path)
            expect(snapshot(service)).to eq(before)
            expect(tmp_paths(service)).to eq(files)
          ensure
            target_exec(service, 'rm', '-f', path)
          end
        end
      end
    end

    it "does not execute #{feature} with disabled target features" do
      expect_refusal(fullname, feature, 'disabled', nil)
    end

    it "does not execute #{feature} with an incorrect token" do
      expect_refusal(fullname, feature, 'secured', wrong_token)
    end
  end

  def management_token
    '6ecebcac-a700-4b54-80ad-ad8d64ed7a4c'
  end

  def wrong_token
    'e121cd92-841e-4aa8-bb73-0b5cb06d3c27'
  end

  def invoke(fullname, service, options = {}, action: 'run', allow_errors: false, command_timeout: 40)
    run_target_module(fullname, service, { 'SSL' => false }.merge(options), action: action, allow_errors: allow_errors, command_timeout: command_timeout)
  end

  def delivery_options(feature, service, flavor, path)
    options = {
      'PAYLOAD' => 'linux/x86/exec', 'CMD' => "/bin/touch #{path}",
      'DisablePayloadHandler' => true, 'WfsDelay' => 0,
      'CMDSTAGER::FLAVOR' => flavor, 'SRVHOST' => listener_host, 'SRVPORT' => 8081,
      'ACL_TOKEN' => service == 'secured' ? management_token : ''
    }
    options['TIMEOUT'] = 5 if feature == 'rexec'
    options
  end

  def expect_refusal(fullname, feature, service, token)
    path = "/tmp/module-target-#{feature}-#{service}-refused"
    before = snapshot(service)
    files = tmp_paths(service)
    target_exec(service, 'test', '!', '-e', path)
    options = delivery_options(feature, service, 'printf', path)
    options['ACL_TOKEN'] = token.to_s
    output = invoke(fullname, service, options, allow_errors: true, command_timeout: 100)
    expect(output).not_to match(/(?:Name|Type|NoMethod|Argument)Error|uninitialized constant|JSON::ParserError/)
    expect(target_exec(service, 'test', '!', '-e', path)).to eq('')
    expect(snapshot(service)).to eq(before)
    expect(tmp_paths(service)).to eq(files)
  end

  def tmp_paths(service)
    target_exec(service, 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1').lines.map(&:strip).sort
  end

  def snapshot(service)
    {
      services: api(service, '/v1/agent/services').keys.sort,
      checks: api(service, '/v1/agent/checks').keys.sort,
      sessions: api(service, '/v1/session/list').map { |row| row.fetch('ID') }.sort,
      rexec_keys: api(service, '/v1/kv/_rexec/?keys').sort
    }
  end

  def api(service, path)
    endpoint = target_endpoint(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 5
    req = Net::HTTP::Get.new(path)
    req['X-Consul-Token'] = management_token if service == 'secured'
    res = http.request(req)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-consul-state.jsonl'), 'a') do |log|
      log.puts(JSON.generate(service: service, path: path, code: res.code.to_i, body: res.body))
    end
    return [] if res.code == '404' && path.start_with?('/v1/kv/')

    expect(res.code).to eq('200')
    JSON.parse(res.body) || []
  end
end
