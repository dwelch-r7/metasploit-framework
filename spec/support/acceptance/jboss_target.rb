require 'digest'
require 'net/http'
require 'rbconfig'

RSpec.shared_context 'native JBoss target' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    # Complete the real console/metadata startup before timed native requests.
    console_command('version')
    argv = [RbConfig.ruby, 'test/module_targets/jboss/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jboss.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jboss-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout).fetch('profiles')
    @warfile = File.join(target_runtime.fetch('artifacts'), 'fixture.war')
    bytes, error, copied = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'open', 'cat', '/opt/module-target/fixture.war')
    expect(copied.success? && error.empty?).to be(true), error
    File.binwrite(@warfile, bytes)
    @war_sha256 = Digest::SHA256.hexdigest(bytes)
    expect(@war_sha256).to eq(target_exec('open', 'sha256sum', '/opt/module-target/fixture.war').split.first)
  end
  def native_http(service, path)
    endpoint = target_endpoint(service)
    Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil).get(path)
  end

  def deployment_files(service)
    target_exec(service, 'find', '/opt/jboss/server/default/deploy', '-mindepth', '1', '-printf', '%P %y\n').lines.map(&:strip).sort
  end

  def deployment_registry(service)
    target_exec(service, '/opt/jboss/bin/twiddle.sh', '-s', 'localhost:1099', 'query', 'jboss.web:j2eeType=WebModule,*').lines.map(&:strip).sort
  end

  def cleanup_new_wars(service, original, registry)
    additions = deployment_files(service) - original
    return if additions.empty?

    # Only remove newly created top-level lab WARs, after assertions have run.
    additions.grep(%r{\A(?:management/)?[^/]+\.war [fd]\z}).each do |entry|
      target_exec(service, 'rm', '-rf', "/opt/jboss/server/default/deploy/#{entry.sub(/ [fd]\z/, '')}")
    end
    wait_for_expect(30, 0.2) { expect(deployment_registry(service)).to eq(registry) }
    File.open(File.join(target_runtime.fetch('artifacts'), 'operator-fallback-cleanup.jsonl'), 'a') do |log|
      log.puts(JSON.generate(service: service, additions: additions, restored: deployment_files(service) == original))
    end
  end

  def with_held_request
    target_exec('open', 'rm', '-f', '/tmp/module-target-jboss-release', '/tmp/module-target-jboss-active')
    endpoint = target_endpoint('open')
    worker = Thread.new do
      request = Net::HTTP::Get.new('/fixture/hold.jsp?token=module-target-jboss-secret')
      request['Host'] = 'jboss.module-target.test'
      Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil).request(request)
    end
    wait_for_expect(60, 0.1) { expect(target_exec('open', 'sh', '-c', 'if test -f /tmp/module-target-jboss-active; then echo active; fi').strip).to eq('active') }
    yield
  ensure
    target_exec('open', 'touch', '/tmp/module-target-jboss-release')
    expect(worker.value.body).to include('module-target-jboss-held-request') if worker
    target_exec('open', 'rm', '-f', '/tmp/module-target-jboss-release', '/tmp/module-target-jboss-active')
  end
end
