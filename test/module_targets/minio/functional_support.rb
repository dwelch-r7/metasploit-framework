# frozen_string_literal: true

require 'ipaddr'
require_relative 'support'

module MinioTarget
  # Pure input/response validation; loading this file never starts a lab.
  module Functional
    CLIENT_KINDS = %w[shell meterpreter].freeze
    CLIENT_CALLS = {
      'default_home' => 2, 'custom_path' => 2, 'missing' => 1, 'empty' => 1,
      'malformed' => 1, 'aliases_empty' => 1, 'default_after_custom' => 3
    }.freeze
    CLIENT_CASES = CLIENT_CALLS.keys.freeze
    CLIENT_STATES_FILE = 'client-states.json'

    def self.initial_client_states(profile)
      return [] if profile == 'fixed'

      CLIENT_KINDS.product(CLIENT_CASES).map do |kind, name|
        { 'kind' => kind, 'name' => name, 'entered' => false, 'completed' => false, 'restored' => false }
      end
    end

    def self.validate_client_states(records, profile)
      expected = initial_client_states(profile).map { |row| row.values_at('kind', 'name') }
      actual = records.map { |row| row.values_at('kind', 'name') } if records.is_a?(Array) && records.all? { |row| row.is_a?(Hash) }
      valid = actual == expected && records.all? do |row|
        %w[entered completed restored].all? { |flag| row[flag] == true } &&
          row['owner_calls'] == CLIENT_CALLS.fetch(row.fetch('name')) && row['cleanup_errors'] == [] && !row.key?('failure')
      end
      raise Error, 'Exact client states must all be entered, completed and restored' unless valid

      true
    end

    def self.settings
      JSON.parse(File.read(File.join(DIRECTORY, 'functional.json')))
    end

    def self.inputs
      MinioTarget.inputs
    end

    def self.framework_inputs
      (ModuleTargetTests::CONSOLE_BUILD_FILES + ['Dockerfile']).sort.to_h do |name|
        [name, Digest::SHA256.file(File.join(ROOT, name)).hexdigest]
      end
    end

    def self.framework_review(path)
      review = JSON.parse(File.read(path))
      valid = review['operation'] == 'canonical_framework_image_review' && review['status'] == 'passed' && review['context_sha256'] == framework_inputs && review['image_id'].to_s.match?(/\Asha256:[0-9a-f]{64}\z/) && !review['image'].to_s.empty? && !review['engine_id'].to_s.empty?
      raise Error, 'An explicit current canonical Framework image review is required' unless valid

      review
    end

    def self.validate_compose(definition, framework_image)
      services = definition.fetch('services')
      raise Error, 'Exactly five functional services required' unless services.keys.sort == %w[framework gateway node1 node2 reporting_db]

      %w[framework reporting_db].each do |name|
        service = services.fetch(name)
        limits = settings.fetch(name)
        image = name == 'framework' ? framework_image : limits.fetch('image')
        valid = service['image'] == image && service['pull_policy'] == 'never' && !service.key?('build') && service.fetch('networks').keys == ['default'] && service.fetch('ports', []).empty? && service['mem_limit'].to_i == limits['memory_bytes'] && service['memswap_limit'].to_i == limits['memory_bytes'] && Rational(service.fetch('cpus').to_s) == Rational(limits.fetch('nano_cpus'), 1_000_000_000) && service['pids_limit'].to_i == limits['pids']
        raise Error, 'Auxiliary image/resources/isolation differs' unless valid
      end
      memory = services.values.sum { |service| service.fetch('mem_limit').to_i }
      cpu = services.values.sum { |service| Rational(service.fetch('cpus').to_s) }
      raise Error, 'Functional aggregate resource budget differs' unless memory == 1600 * 1024 * 1024 && cpu == Rational(235, 100)

      true
    end

    def self.internal_endpoints(containers, networks, project)
      by_role = containers.to_h { |row| [row.fetch('Config').fetch('Labels').fetch('com.docker.compose.service'), row] }
      raise Error, 'Unexpected actual functional service set' unless containers.length == 5 && by_role.keys.sort == %w[framework gateway node1 node2 reporting_db] && containers.all? { |row| row.dig('Config', 'Labels', 'com.docker.compose.project') == project }

      default = networks.select { |row| row.dig('Labels', 'com.docker.compose.project') == project && row.dig('Labels', 'com.docker.compose.network') == 'default' }
      public_network = networks.select { |row| row.dig('Labels', 'com.docker.compose.project') == project && row.dig('Labels', 'com.docker.compose.network') == 'public' }
      raise Error, 'Exact internal/default and public networks required' unless networks.length == 2 && default.length == 1 && public_network.length == 1 && default[0]['Internal'] == true && public_network[0]['Internal'] == false

      by_role.each do |name, container|
        memberships = container.fetch('NetworkSettings').fetch('Networks').values
        expected = name == 'gateway' ? [default[0]['Id'], public_network[0]['Id']] : [default[0]['Id']]
        raise Error, 'Actual service network membership differs' unless memberships.map { |entry| entry.fetch('NetworkID') }.sort == expected.sort
      end
      address = lambda do |name|
        entry = by_role.fetch(name).fetch('NetworkSettings').fetch('Networks').values.find { |row| row['NetworkID'] == default[0]['Id'] }
        ip = IPAddr.new(entry.fetch('IPAddress'))
        raise Error, 'Missing usable internal IPv4' unless ip.ipv4? && !ip.loopback? && !ip.to_i.zero?

        ip.to_s
      end
      host = address.call('gateway')
      endpoints = MinioTarget.assets.fetch('native').fetch('gateway').fetch('ports').transform_values { |port| { 'host' => host, 'port' => port } }
      [endpoints, address.call('framework')]
    rescue IPAddr::InvalidAddressError, KeyError => e
      raise Error, "Invalid actual functional topology: #{e.message}"
    end

    def self.actual_resources(containers)
      containers.each do |container|
        role = container.fetch('Config').fetch('Labels').fetch('com.docker.compose.service')
        limits = case role
                 when 'node1', 'node2' then MinioTarget.assets.fetch('native')
                 when 'gateway' then MinioTarget.assets.fetch('native').fetch('gateway')
                 else settings.fetch(role)
                 end
        actual = container.fetch('HostConfig')
        valid = actual['Memory'] == limits['memory_bytes'] && actual['MemorySwap'] == limits['memory_bytes'] && actual['NanoCpus'] == limits['nano_cpus'] && actual['PidsLimit'] == limits['pids'] && actual['Privileged'] == false
        raise Error, 'Actual functional host limits/privilege differ' unless valid

        bindings = actual.fetch('PortBindings', {}) || {}
        if role == 'gateway'
          raise Error, 'Actual gateway publication differs' unless bindings.keys.sort == %w[19001/tcp 19002/tcp] && bindings.values.all? { |ports| ports.length == 1 && ports[0]['HostIp'] == '127.0.0.1' }
        else
          raise Error, 'Unexpected published target/database/handler port' unless bindings.empty?
        end
      end
      true
    end

    # @param text [String] actual HttpTrace console response with ANSI removed
    # @return [Hash] content-length-delimited actual HTTP response
    def self.bootstrap_trace(text)
      marker = "# Response:\n####################\n"
      block = text.split(marker, -1)
      raise Error, 'Expected exactly one actual traced response' unless block.length == 2

      match = block.last.match(%r{\AHTTP/1\.[01] ([0-9]{3})[^\r\n]*\r?\n(.*?)\r?\n\r?\n}m)
      raise Error, 'Traced HTTP response headers missing' unless match

      headers = match[2].lines.to_h { |line| line.strip.split(/:\s*/, 2) }
      length = headers.find { |key, _| key.downcase == 'content-length' }&.last
      raise Error, 'Traced response needs an exact content length' unless length&.match?(/\A[0-9]+\z/)

      body = block.last.b.byteslice(match.end(0), Integer(length))
      raise Error, 'Traced response body truncated' unless body && body.bytesize == Integer(length)

      { 'status' => Integer(match[1]), 'headers' => headers, 'body' => body.force_encoding(Encoding::UTF_8) }
    end

    def self.bootstrap_loot(raw, response_body)
      actual = JSON.parse(raw)
      response = JSON.parse(response_body)
      raise Error, 'Actual loot must be the complete genuine JSON disclosure' unless actual.is_a?(Hash) && actual == response && actual['MinioEnv'].is_a?(Hash) && actual['MinioEnv'].all? { |key, value| key.is_a?(String) && value.is_a?(String) }

      actual
    rescue JSON::ParserError => e
      raise Error, "Actual owner loot is not valid JSON: #{e.message}"
    end
  end
end
