# frozen_string_literal: true

require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'rexml/document'
require 'uri'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
expected = JSON.parse(File.read(File.join(__dir__, 'vendor-files.json')))
records = { commands: [], requests: [], profiles: {} }
command = lambda do |service, *arguments|
  argv = runtime.fetch('compose') + ['exec', '-T', service] + arguments
  stdout, stderr, status = Open3.capture3(*argv)
  records[:commands] << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native inspector command failed: #{service}: #{stderr}" unless status.success? && stderr.empty?

  stdout
end

%w[open legacy secured].each do |service|
  files = command.call(service, 'sha256sum', *expected.keys.map { |path| "/opt/jboss/#{path}" })
  expected.each do |path, digest|
    raise "Vendor source changed: #{path}" unless files.lines.any? { |line| line.strip == "#{digest}  /opt/jboss/#{path}" }
  end
  ant = command.call(service, 'java', '-cp', '/opt/module-target/compiler/ant.jar:/opt/module-target/compiler/ant-launcher.jar', 'org.apache.tools.ant.Main', '-version')
  raise 'Native Ant version mismatch' unless ant.include?('Apache Ant(TM) version 1.10.15')

  xml = command.call(service, 'cat', '/opt/jboss/server/default/deploy/jboss-web.deployer/conf/web.xml')
  config = REXML::Document.new(xml).get_elements("//servlet[servlet-name='jsp']/init-param").to_h { |element| [element.elements['param-name'].text, element.elements['param-value'].text] }
  raise 'Native JSP compiler configuration mismatch' unless config.values_at('compiler', 'fork', 'compilerSourceVM', 'compilerTargetVM') == %w[javac1.8 true 1.5 1.5]

  native = command.call(service, '/opt/jboss/bin/twiddle.sh', '-s', 'localhost:1099', 'get', 'jboss.system:type=ServerInfo', 'OSName', 'OSArch', 'JavaVersion').lines.to_h { |line| line.strip.split('=', 2) }
  endpoint = runtime.fetch('endpoints').fetch(service)
  responses = %w[GET POST].to_h do |method|
    path = '/jmx-console/HtmlAdaptor?' + URI.encode_www_form(action: 'inspectMBean', name: 'jboss.system:type=ServerInfo')
    request = method == 'GET' ? Net::HTTP::Get.new(path) : Net::HTTP::Post.new(path)
    request.basic_auth('admin', service == 'legacy' ? 'module-target-admin-password' : 'admin') unless service == 'open'
    response = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil).request(request)
    document = Nokogiri::HTML(response.body)
    values = document.css('tr').filter_map do |row|
      cells = row.css('td').map { |cell| cell.text.strip }
      [cells[0], cells[3]] if native.key?(cells[0])
    end.to_h
    record = { service: service, method: method, path: path, code: response.code.to_i, headers: response.to_hash, body: response.body, values: values }
    records[:requests] << record
    raise "Native HTTP inspector failed: #{service}/#{method}" unless response.code == '200' && document.at_css('title')&.text == 'MBean Inspector' && values == native

    [method, record]
  end
  records[:profiles][service] = { vendor_files: files, ant: ant, configuration: config, native: native, responses: responses }
end

puts JSON.pretty_generate(records)
