# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'
require 'uri'
require 'base64'

# Real JBoss policy, MBean and deployment controls, independent of Framework.
class NativeJBossProbe
  def initialize
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @records = { profiles: {}, commands: [], requests: [] }
  end

  def run
    %w[open legacy secured].each do |service|
      version = cli(service, 'get', 'jboss.system:type=Server', 'Version')
      raise 'Native JBoss version mismatch' unless version.include?('Version=4.2.3.GA')

      info = cli(service, 'get', 'jboss.system:type=ServerInfo', 'JavaVersion', 'OSName', 'OSArch')
      raise 'Native runtime mismatch' unless info.include?('JavaVersion=1.8.0_412') && info.include?('OSName=Linux')

      ports = local_ports(service)
      raise 'Native JBoss listener mismatch' unless ports == "1098=open\n1099=open\n4444=open\n"

      policies = %w[GET POST HEAD].to_h do |method|
        response = request(service, '/jmx-console/HtmlAdaptor', method: method)
        expected = if method == 'HEAD' && service != 'secured'
                     500 # Vendor RequestDispatcher rejects the doHead wrapper after dispatch.
                   else
                     service == 'open' ? 200 : 401
                   end
        raise "Native #{service} #{method} management policy mismatch" unless response[:code] == expected

        [method, response]
      end
      password = service == 'secured' ? 'admin' : 'module-target-admin-password'
      unless service == 'open'
        correct = request(service, '/jmx-console/HtmlAdaptor', user: 'admin', password: password)
        wrong = request(service, '/jmx-console/HtmlAdaptor', user: 'admin', password: 'wrong-password')
        raise 'Native credential policy mismatch' unless correct[:code] == 200 && wrong[:code] == 401 && correct[:body].include?('JBoss')
      end
      status = request(service, '/status')
      raise 'Native status policy mismatch' unless status[:code] == (service == 'open' ? 200 : 401)

      paths = %w[/jmx-console/checkJNDI.jsp /web-console/ServerInfo.jsp /web-console/Invoker /invoker/JMXInvokerServlet /invoker/readonly /admin-console/login.seam]
      scanned = paths.to_h { |path| [path, request(service, path)] }
      %w[jboss.deployer:service=BSHDeployer jboss.admin:service=DeploymentFileRepository jboss.system:service=MainDeployer].each do |name|
        result = cli(service, 'info', name)
        raise "Native MBean unavailable: #{name}" unless result.include?('+++ Operations:')
      end
      method = service == 'legacy' ? 'HEAD' : 'POST'
      auth = service == 'secured' ? { user: 'admin', password: password } : {}
      bsh = 2.times.map do
        proof = '/tmp/module-target-jboss-native-bsh'
        script = "new java.io.FileOutputStream(\"#{proof}\").write(\"native-bsh-executed\".getBytes());"
        response = invoke(service, 'jboss.deployer:service=BSHDeployer', 'createScriptDeployment', [['java.lang.String', script], ['java.lang.String', 'module-target-native.bsh']], method: method, **auth)
        raise 'Native BSH execution failed' unless command(service, 'cat', proof) == 'native-bsh-executed'

        command(service, 'rm', proof)
        response
      end
      repository = 2.times.map do
        body = '<% response.setContentType("text/plain"); out.print("native-repository-executed:" + System.getProperty("java.version")); %>'
        stored = invoke(service, 'jboss.admin:service=DeploymentFileRepository', 'store', [['java.lang.String', 'module-target-native.war'], ['java.lang.String', 'index'], ['java.lang.String', '.jsp'], ['java.lang.String', body], ['boolean', 'true']], method: method, **auth)
        deployed = await_response(service, '/module-target-native/index.jsp', 200)
        raise 'Native repository JSP execution failed' unless deployed[:body] == 'native-repository-executed:1.8.0_412'

        invoke(service, 'jboss.admin:service=DeploymentFileRepository', 'remove', [['java.lang.String', 'module-target-native.war'], ['java.lang.String', 'index'], ['java.lang.String', '.jsp']], method: method, **auth)
        invoke(service, 'jboss.admin:service=DeploymentFileRepository', 'remove', [['java.lang.String', './'], ['java.lang.String', 'module-target-native.war'], ['java.lang.String', '']], method: method, **auth)
        removed = await_response(service, '/module-target-native/index.jsp', 404)
        command(service, 'test', '!', '-e', '/opt/jboss/server/default/deploy/management/module-target-native.war')
        { stored: stored, deployed: deployed, removed: removed }
      end
      confirmation = service == 'legacy' ? confirm_bsh_stager : nil

      before = registry(service)
      deploys = 2.times.map do
        cli(service, 'invoke', 'jboss.system:service=MainDeployer', 'deploy', 'file:/opt/module-target/fixture.war')
        deployed = await_response(service, '/fixture/index.jsp', 200)
        raise 'Native JSP did not execute' unless ['module-target-jboss-native', 'account=root', 'java=1.8.0_412'].all? { |text| deployed[:body].include?(text) }

        active_registry = registry(service)
        raise 'Native deployment missing from registry' unless active_registry.any? { |name| name.include?('name=//localhost/fixture,') }

        cli(service, 'invoke', 'jboss.system:service=MainDeployer', 'undeploy', 'file:/opt/module-target/fixture.war')
        removed = await_response(service, '/fixture/index.jsp', 404)
        raise 'Native registry did not restore' unless registry(service) == before

        { deployed: deployed, active_registry: active_registry, removed: removed }
      end
      # A real benign app remains available for concurrent status requests and
      # supplies the exact native-built WAR for the admin deployment modules.
      cli(service, 'invoke', 'jboss.system:service=MainDeployer', 'deploy', 'file:/opt/module-target/fixture.war')
      await_response(service, '/fixture/index.jsp', 200)
      @records[:profiles][service] = { version: version, runtime: info, ports: ports, policies: policies, status: status, scanned: scanned, bsh: bsh, bsh_confirmation: confirmation, repository: repository, deployments: deploys, registry: registry(service) }
    end
    unrelated = request('unrelated', '/')
    raise 'Unrelated HTTP identity mismatch' unless unrelated[:code] == 200 && unrelated[:body].include?('module-target-http-marker')
    raise 'Unrelated listener control mismatch' unless local_ports('unrelated') == "1098=closed\n1099=closed\n4444=closed\n"

    unrelated_paths = %w[/jmx-console/HtmlAdaptor /jmx-console/checkJNDI.jsp /status /web-console/ServerInfo.jsp /web-console/Invoker /invoker/JMXInvokerServlet /invoker/readonly /admin-console/login.seam].to_h { |path| [path, request('unrelated', path)] }
    raise 'Unrelated management paths unexpectedly exist' unless unrelated_paths.values.all? { |response| response[:code] == 404 }

    @records[:unrelated] = unrelated
    @records[:unrelated_paths] = unrelated_paths
    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-jboss-partial.json'), JSON.pretty_generate(@records))
  end

  def confirmation_only
    @records[:bsh_confirmation] = confirm_bsh_stager
    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-jboss-confirmation-partial.json'), JSON.pretty_generate(@records))
  end

  private

  def confirm_bsh_stager
    service = 'legacy'
    before = registry(service)
    source = command(service, 'base64', '--wrap=0', '/opt/module-target/bsh-stager.jsp')
    war = command(service, 'base64', '--wrap=0', '/opt/module-target/fixture.war')
    path = '/opt/jboss/server/default/deploy'
    2.times.map do
      script = "new java.io.File(\"#{path}/module-target-native-bsh.war\").mkdir(); new java.io.FileOutputStream(\"#{path}/module-target-native-bsh.war/upload.jsp\").write(new sun.misc.BASE64Decoder().decodeBuffer(\"#{source}\"));"
      response = invoke(service, 'jboss.deployer:service=BSHDeployer', 'createScriptDeployment', [['java.lang.String', script], ['java.lang.String', 'module-target-confirmation.bsh']], method: 'HEAD')
      raise 'Native HEAD confirmation control changed status' unless response[:code] == 500

      # This is the byte-exact module-emitted stager. Its parameterless GET
      # catches NoSuchElementException before it opens the destination WAR.
      confirmed = await_response(service, '/module-target-native-bsh/upload.jsp', 200)
      raise 'Native stager confirmation body was not empty' unless confirmed[:body].to_s.strip.empty?

      command(service, 'test', '!', '-e', "#{path}/module-target-admin.war")
      uploaded = request(service, '/module-target-native-bsh/upload.jsp', method: 'POST', data: URI.encode_www_form('archive' => war))
      raise 'Native stager upload failed' unless uploaded[:code] == 200

      deployed = await_response(service, '/module-target-admin/index.jsp', 200)
      raise 'Native confirmation WAR did not execute' unless deployed[:body].include?('module-target-jboss-native')
      raise 'Native confirmation WAR bytes changed' unless command(service, 'sha256sum', "#{path}/module-target-admin.war").split.first == command(service, 'sha256sum', '/opt/module-target/fixture.war').split.first

      deletion = "new java.io.File(\"#{path}/module-target-admin.war\").delete(); new java.io.File(\"#{path}/module-target-native-bsh.war/upload.jsp\").delete(); new java.io.File(\"#{path}/module-target-native-bsh.war\").delete();"
      removed = invoke(service, 'jboss.deployer:service=BSHDeployer', 'createScriptDeployment', [['java.lang.String', deletion], ['java.lang.String', 'module-target-confirmation-cleanup.bsh']], method: 'HEAD')
      raise 'Native HEAD deletion control changed status' unless removed[:code] == 500

      await_response(service, '/module-target-admin/index.jsp', 404)
      await_response(service, '/module-target-native-bsh/upload.jsp', 404)
      command(service, 'test', '!', '-e', "#{path}/module-target-admin.war")
      command(service, 'test', '!', '-e', "#{path}/module-target-native-bsh.war")
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
      until registry(service) == before
        raise 'Native BSH confirmation registry did not restore' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.1
      end
      { response: response, confirmed: confirmed, uploaded: uploaded, deployed: deployed, removed: removed }
    end
  end

  def cli(service, *)
    command(service, '/opt/jboss/bin/twiddle.sh', '-s', 'localhost:1099', *)
  end

  def command(service, *arguments)
    argv = @runtime.fetch('compose') + ['exec', '-T', '-e', 'JAVA_OPTS=-Djava.net.preferIPv4Stack=true', service] + arguments
    stdout, stderr, status = Open3.capture3(*argv)
    @records[:commands] << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
    raise "Native vendor command failed: #{argv.inspect}: #{stderr}" unless status.success? && stderr.empty?

    stdout
  end

  def registry(service)
    cli(service, 'query', 'jboss.web:j2eeType=WebModule,*').lines.map(&:strip).sort
  end

  def local_ports(service)
    command(service, 'bash', '-c', 'for port in 1098 1099 4444; do if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then echo "$port=open"; else echo "$port=closed"; fi; done')
  end

  def invoke(service, name, operation, arguments, method:, **auth)
    pairs = [['action', 'invokeOpByName'], ['name', name], ['methodName', operation]]
    arguments.each_with_index { |(type, value), index| pairs.concat([['argType', type], ["arg#{index}", value]]) }
    path = '/jmx-console/HtmlAdaptor'
    data = URI.encode_www_form(pairs)
    path += "?#{data}" unless method == 'POST'
    request(service, path, method: method, data: method == 'POST' ? data : nil, **auth)
  end

  def request(service, path, method: 'GET', user: nil, password: nil, data: nil)
    endpoint = @runtime.fetch('endpoints').fetch(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    request = Net::HTTPGenericRequest.new(method, !data.nil?, method != 'HEAD', path)
    request['Content-Type'] = 'application/x-www-form-urlencoded' if data
    request.body = data
    request.basic_auth(user, password) if user
    response = http.request(request)
    body = response.body&.dup&.force_encoding(Encoding::UTF_8)
    binary = body && !body.valid_encoding?
    record = { service: service, path: path, method: method, user: user, data: data, code: response.code.to_i, headers: response.to_hash, body: binary ? nil : body }
    record[:body_base64] = Base64.strict_encode64(response.body) if binary
    @records[:requests] << record
    record
  end

  def await_response(service, path, code)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
    loop do
      response = request(service, path)
      return response if response[:code] == code

      raise "Native #{path} did not become #{code}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.1
    end
  end
end

probe = NativeJBossProbe.new
puts JSON.pretty_generate(ARGV == ['--bsh-confirmation-only'] ? probe.confirmation_only : probe.run)
