# frozen_string_literal: true

require 'base64'
require 'json'
require_relative 'profiles'

# Retain phase/role evidence before failing a resource-pressure check.
module WordPressAdminResourceCounters
  class CounterError < StandardError; end

  COUNTERS = {
    'memory.events' => { required: %w[max oom oom_kill oom_group_kill], zero: %w[oom oom_kill oom_group_kill] },
    'pids.events' => { required: %w[max], zero: %w[max] }
  }.freeze

  def wordpress_resource_counters(phase)
    profile = WordPressAdminProfiles.fetch(ENV.fetch('WORDPRESS_ADMIN_PROFILE', 'root'))
    report = { phase: phase, roles: {}, errors: [] }
    WordPressAdminProfiles.roles(profile).each do |service|
      observations = report.fetch(:roles)[service] = {}
      COUNTERS.each do |counter, rules|
        observation = observations[counter] = {}
        begin
          output = target_exec(service, 'cat', "/sys/fs/cgroup/#{counter}")
          raise TypeError, 'Counter output is not a string' unless output.is_a?(String)

          observation[:raw_base64] = Base64.strict_encode64(output)
          values = observation[:values] = wordpress_counter_values(output)
          missing = rules.fetch(:required) - values.keys
          raise ArgumentError, "Missing counter keys: #{missing.join(', ')}" unless missing.empty?

          exceeded = rules.fetch(:zero).reject { |key| values.fetch(key) == 0 }
          raise CounterError, "Nonzero counters: #{exceeded.map { |key| "#{key}=#{values.fetch(key)}" }.join(', ')}" unless exceeded.empty?
        rescue StandardError => e
          # Keep every role/file observation before failing the phase, including
          # unexpected collector errors; none are converted into a passing result.
          observation[:error] = { class: e.class.name, message: e.message }
          report.fetch(:errors) << "#{service} #{counter}: #{e.class}: #{e.message}"
        end
      end
    end
    # memory.events:max records reclaimable boundary crossings, not OOM kills.
    # https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files
    report[:memory_max_informational] = true
    File.write(File.join(target_runtime.fetch('artifacts'), "wordpress-resource-counters-#{phase}.json"), JSON.pretty_generate(report))
    raise CounterError, "WordPress resource counters #{phase} failed: #{report.fetch(:errors).join('; ')}" unless report.fetch(:errors).empty?

    report
  end

  def wordpress_counter_values(output)
    output.each_line.each_with_object({}) do |line, values|
      key, value, *extra = line.split
      unless key&.match?(/\A[a-z_]+\z/) && value&.match?(/\A[0-9]+\z/) && extra.empty?
        raise ArgumentError, 'Malformed counter line'
      end
      raise ArgumentError, "Duplicate counter key: #{key}" if values.key?(key)

      values[key] = Integer(value, 10)
    end
  end
end

RSpec.shared_context 'WordPress administrator resource counters' do
  include WordPressAdminResourceCounters

  before(:all) { wordpress_resource_counters('before') }
  after(:all) { wordpress_resource_counters('after') }
end
