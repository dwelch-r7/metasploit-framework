# frozen_string_literal: true

require 'json'
require 'open3'
require 'shellwords'

# Independent vendor decoding, JMS delivery and real OpenWire execution controls.
class NativeActiveMqProbe
  CLASSPATH = '/opt/module-target:/opt/activemq/lib/*:/opt/activemq/lib/optional/*'

  def initialize
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @records = { profiles: {}, commands: [] }
  end

  def run
    { 'affected' => '5.18.2', 'fixed' => '5.18.3' }.each do |service, version|
      java = command(service, 'java', '-version')
      info = control(service, 'info')
      raise 'Native OpenWire product mismatch' unless field(info, 'OPENWIRE_NAME') == 'ActiveMQ'
      raise 'Native OpenWire version mismatch' unless field(info, 'OPENWIRE_VERSION') == version

      body = command(service, 'curl', '--fail', '--silent', '--user', 'admin:admin', '--header', 'Origin: http://127.0.0.1:8161', 'http://127.0.0.1:8161/api/jolokia/read/org.apache.activemq:type=Broker,brokerName=localhost/BrokerVersion')
      json = JSON.parse(body)
      raise 'Native JMX broker version mismatch' unless json['status'] == 200 && json['value'] == version

      process = command(service, 'ps', '-ww', '-eo', 'pid,user,comm,args')
      pid = broker_pid(process)
      before = directory(service)
      attempts = 2.times.map do |index|
        jms(service)
        path = "/tmp/module-target-native-openwire-#{index}"
        command(service, 'test', '!', '-e', path)
        response = control(service, 'openwire', path)
        present = field(response, 'PROOF_PRESENT') == 'true'
        raise 'Native OpenWire execution policy mismatch' unless present == (service == 'affected')

        if present
          raise 'Native proof was not created by the broker process' unless command(service, 'cat', path).to_i == pid
          raise 'Native proof owner mismatch' unless command(service, 'stat', '-c', '%U', path).strip == 'activemq'
          raise 'Native proof has no actual XML callback' unless field(response, 'XML_REQUEST_COUNT').to_i.positive?

          command(service, 'rm', path)
        else
          raise 'Patched broker unexpectedly fetched XML' unless field(response, 'XML_REQUEST_COUNT') == '0'

          command(service, 'test', '!', '-e', path)
        end
        jms(service)
        raise 'Native temporary directory was not restored' unless directory(service) == before

        { output: response, executed: present }
      end
      @records[:profiles][service] = { version: version, java: java, openwire: info, jmx: json, processes: process, broker_pid: pid, attempts: attempts }
    end
    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-activemq-partial.json'), JSON.pretty_generate(@records))
  end

  private

  def command(service, *arguments)
    stdout, stderr, status = Open3.capture3(*@runtime.fetch('compose'), 'exec', '-T', service, *arguments)
    @records[:commands] << { service: service, argv: arguments, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
    raise "Native command failed on #{service}: #{arguments.inspect}: #{stderr}#{stdout}" unless status.success?

    # java -version intentionally writes the actual runtime identity to stderr.
    arguments == ['java', '-version'] ? stdout + stderr : stdout
  end

  def control(service, *)
    command(service, 'java', '-Xmx128m', '-cp', CLASSPATH, 'NativeControl', *)
  end

  def jms(service)
    output = control(service, 'jms')
    raise 'Native JMS delivery or removal failed' unless field(output, 'JMS_ROUNDTRIP') == 'matched' && field(output, 'JMS_DESTINATION_REMOVED') == 'true'
  end

  def field(output, name)
    prefix = "#{name}="
    values = output.lines.filter_map { |line| line.delete_prefix(prefix).strip if line.start_with?(prefix) }
    raise "Native #{name} field missing or duplicated" unless values.length == 1

    values.first
  end

  def broker_pid(output)
    pids = output.lines.filter_map do |line|
      pid, user, process, arguments = line.strip.split(/\s+/, 4)
      next unless process == 'java' && user == 'activemq'

      values = Shellwords.shellsplit(arguments)
      index = values.index('-jar')
      pid.to_i if index && File.expand_path(values[index + 1]) == '/opt/activemq/bin/activemq.jar'
    end
    raise 'Native broker Java process missing or duplicated' unless pids.length == 1

    pids.first
  end

  def directory(service)
    command(service, 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-printf', "%f\n").lines.map(&:strip).sort
  end
end

puts JSON.pretty_generate(NativeActiveMqProbe.new.run) if $PROGRAM_NAME == __FILE__
