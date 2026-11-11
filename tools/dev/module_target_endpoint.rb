# frozen_string_literal: true

require 'ipaddr'

# Select an explicitly named internal network shared with an isolated console.
# Inspection callbacks retain the runner's bounded command capture and cleanup.
class ModuleTargetEndpoint
  # @param name [String] logical Compose network name
  # @return [String] validated logical network name
  def self.validate_network_name(name)
    raise ArgumentError, 'Module endpoint network must be a logical Compose network name' unless name.is_a?(String) && name.match?(/\A[a-zA-Z0-9][a-zA-Z0-9_-]*\z/)

    name
  end

  # @param project [String] exact project selected in the Compose command
  # @param network [String] logical internal Compose network name
  # @param container [Proc] inspection callback taking a service name
  # @param network_inspection [Proc] inspection callback taking a network ID
  def initialize(project:, network:, container:, network_inspection:)
    raise ArgumentError, 'Module endpoint selection requires an explicit Compose project' unless project.is_a?(String) && project.match?(/\A[a-z0-9][a-z0-9_-]*\z/)

    @project = project
    @network = self.class.validate_network_name(network)
    @container = container
    @network_inspection = network_inspection
  end

  # @param service [String] endpoint service name
  # @return [String] actual IPv4 address on the owned internal console network
  def address(service)
    frame = @container.call('framework')
    validate_container(frame, 'framework')
    frame_memberships = memberships(frame)
    raise ArgumentError, 'Framework must have exactly one isolated network' unless frame_memberships.length == 1

    target = service == 'framework' ? frame : @container.call(service)
    validate_container(target, service)
    target_memberships = memberships(target)
    network_ids = (frame_memberships + target_memberships).map { |row| row.fetch('NetworkID') }.uniq
    definitions = network_ids.to_h do |identifier|
      definition = @network_inspection.call(identifier)
      labels = definition.fetch('Labels')
      valid = definition['Id'] == identifier && labels.is_a?(Hash) && labels['com.docker.compose.project'] == @project && labels['com.docker.compose.network'].is_a?(String) && !labels['com.docker.compose.network'].empty?
      raise ArgumentError, 'Module endpoint network ownership differs' unless valid

      [identifier, definition]
    end
    names = definitions.values.map { |row| row.fetch('Labels').fetch('com.docker.compose.network') }
    raise ArgumentError, 'Module endpoint network names are ambiguous' unless names.uniq.length == names.length

    selected = definitions.select { |_identifier, row| row.dig('Labels', 'com.docker.compose.network') == @network }
    raise ArgumentError, 'Expected one selected module endpoint network' unless selected.length == 1

    identifier, definition = selected.first
    raise ArgumentError, 'Selected module endpoint network must be internal' unless definition['Internal'] == true
    raise ArgumentError, 'Module endpoint must share the isolated Framework network' unless frame_memberships.first['NetworkID'] == identifier

    matching = target_memberships.select { |row| row['NetworkID'] == identifier }
    raise ArgumentError, 'Module endpoint lacks the selected Framework network' unless matching.length == 1

    address = matching.first.fetch('IPAddress')
    begin
      parsed = IPAddr.new(address) if address.is_a?(String)
    rescue IPAddr::InvalidAddressError
      parsed = nil
    end
    raise ArgumentError, 'Module endpoint lacks a valid IPv4 address' unless parsed&.ipv4? && !parsed.loopback? && address != '0.0.0.0' && !address.include?('/')

    address
  end

  private

  def validate_container(container, service)
    valid = container.dig('Config', 'Labels', 'com.docker.compose.project') == @project && container.dig('Config', 'Labels', 'com.docker.compose.service') == service && container.dig('State', 'Running') == true
    raise ArgumentError, "Module endpoint container ownership/state differs for #{service}" unless valid
  end

  def memberships(container)
    networks = container.fetch('NetworkSettings').fetch('Networks')
    valid = networks.is_a?(Hash) && !networks.empty? && networks.values.all? { |row| row.is_a?(Hash) && row['NetworkID'].is_a?(String) && !row['NetworkID'].empty? }
    raise ArgumentError, 'Module endpoint network membership is malformed' unless valid

    rows = networks.values
    raise ArgumentError, 'Module endpoint network memberships are ambiguous' unless rows.map { |row| row.fetch('NetworkID') }.uniq.length == rows.length

    rows
  end
end
