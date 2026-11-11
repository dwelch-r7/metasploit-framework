#!/usr/bin/env ruby
# frozen_string_literal: true

require 'ipaddr'
require_relative '../../../tools/dev/run_guarded_module_target_tests'

# Keep the shared runner's single-network policy unchanged for other families.
# This lab's genuine HTTP gateway also has a public loopback-facing network.
class SupersetCookieRunner < GuardedModuleTargetTests
  private

  def container_ip(compose, service)
    raise ResourceRefusal, 'Unexpected Superset endpoint role' unless %w[gateway framework].include?(service)

    frame = inspected(compose_output(compose, 'ps', '--quiet', 'framework').strip, 'container').fetch(0)
    frame_networks = frame.fetch('NetworkSettings').fetch('Networks').values
    raise ResourceRefusal, 'Framework must have exactly one network' unless frame_networks.length == 1

    project = frame.fetch('Config').fetch('Labels').fetch('com.docker.compose.project')
    network_id = frame_networks.first.fetch('NetworkID')
    network = inspected(network_id, 'network').fetch(0)
    valid = network['Internal'] == true && network.dig('Labels', 'com.docker.compose.project') == project && network.dig('Labels', 'com.docker.compose.network') == 'default'
    raise ResourceRefusal, 'Framework network is not the owned internal default' unless valid

    target = service == 'framework' ? frame : inspected(compose_output(compose, 'ps', '--quiet', service).strip, 'container').fetch(0)
    labels = target.fetch('Config').fetch('Labels')
    raise ResourceRefusal, 'Superset endpoint ownership differs' unless labels['com.docker.compose.project'] == project && labels['com.docker.compose.service'] == service

    memberships = target.fetch('NetworkSettings').fetch('Networks').values
    matches = memberships.select { |row| row['NetworkID'] == network_id }
    raise ResourceRefusal, 'Superset endpoint lacks one internal address' unless matches.length == 1

    if service == 'gateway'
      public_ids = memberships.map { |row| row.fetch('NetworkID') } - [network_id]
      raise ResourceRefusal, 'Gateway must have exactly two networks' unless public_ids.length == 1 && memberships.length == 2

      public_network = inspected(public_ids.first, 'network').fetch(0)
      valid = public_network['Internal'] == false && public_network.dig('Labels', 'com.docker.compose.project') == project && public_network.dig('Labels', 'com.docker.compose.network') == 'public'
      raise ResourceRefusal, 'Gateway public network ownership differs' unless valid
    end
    address = matches.first.fetch('IPAddress')
    raise ResourceRefusal, 'Superset endpoint lacks a valid IPv4 address' unless IPAddr.new(address).ipv4? && address != '0.0.0.0'

    address
  end

  def inspected(identifier, kind)
    output = +''
    passed = command(['docker', kind, 'inspect', identifier], path: File.join(@results, 'superset-endpoints.log'), timeout: 30, capture: output, quiet: true)
    raise ResourceRefusal, "Could not inspect Superset #{kind}" unless passed

    JSON.parse(output)
  end
end

if $PROGRAM_NAME == __FILE__
  abort 'Usage: bundle exec ruby test/module_targets/superset_cookie/run.rb' unless ARGV.empty?
  exit SupersetCookieRunner.new.run(['superset_cookie'])
end
