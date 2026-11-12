# frozen_string_literal: true

require 'json'
require 'timeout'

threads = []
trace = nil
release = Queue.new
result = { mode: ARGV.fetch(0), events: [] }

begin
  Timeout.timeout(15) do
    require 'msfenv'
    require 'rex/post/meterpreter/client'

    mapper = Rex::Post::Meterpreter::ExtensionMapper
    feature = 'rex/post/meterpreter/extensions/stdapi/stdapi'
    full_path = File.expand_path('../../../../../lib/' + feature + '.rb', __dir__)
    dir_path = File.join(File.dirname(full_path), 'fs/dir.rb')
    snapshot = lambda do
      extensions = Rex::Post::Meterpreter::Extensions
      namespace = extensions.const_get(:Stdapi, false) if extensions.const_defined?(:Stdapi, false)
      {
        feature_loaded: $LOADED_FEATURES.include?(full_path),
        index_cached: Bootsnap::LoadPathCache.loaded_features_index&.key?(feature) || false,
        namespace_defined: !namespace.nil?,
        class_defined: namespace&.const_defined?(:Stdapi, false) || false,
        mapper_cached: mapper.class_variable_get(:@@klasses).key?('stdapi')
      }
    end
    describe_class = lambda do |klass|
      unless klass.is_a?(Class) && klass.name == 'Rex::Post::Meterpreter::Extensions::Stdapi::Stdapi' && klass.extension_id == 1000
        raise 'Mapper returned an unexpected extension class'
      end

      { name: klass.name, extension_id: klass.extension_id, source: klass.method(:extension_id).source_location }
    end
    result[:ruby] = RUBY_DESCRIPTION
    result[:bootsnap] = Bootsnap::VERSION
    result[:initial] = snapshot.call
    raise 'Probe was not cold' if result[:initial].values_at(:feature_loaded, :index_cached, :class_defined, :mapper_cached).any?
    raise 'Bootsnap load-path cache was not enabled initially' unless Bootsnap::LoadPathCache.enabled?

    if result[:mode] == 'sequential'
      first = mapper.get_extension_klass('stdapi'.dup)
      second = mapper.get_extension_klass('stdapi'.dup)
      result[:first] = describe_class.call(first)
      result[:second] = describe_class.call(second)
      result[:same_class] = first.equal?(second)
      first_module = mapper.get_extension_module('stdapi'.dup)
      second_module = mapper.get_extension_module('stdapi'.dup)
      result[:same_module] = first_module.equal?(second_module)
      raise 'Cached identities changed' unless result[:same_class] && result[:same_module]
    elsif result[:mode] == 'failure_then_valid'
      failed = Queue.new
      first = Thread.new do
        begin
          mapper.get_extension_module('__extension_probe_missing__'.dup)
          failed << { error: 'Missing extension unexpectedly loaded' }
        rescue RuntimeError => e
          failed << { value: { error: e.class.name, message: e.message } }
        end
        release.pop
      end
      threads << first
      result[:first] = failed.pop
      raise 'Missing-extension failure contract changed' unless result[:first].dig(:value, :error) == 'Rex::RuntimeError'

      second = Thread.new { describe_class.call(mapper.get_extension_klass('stdapi'.dup)) }
      threads << second
      raise 'Failed lookup retained the loading lock' unless second.join(5)

      result[:second] = { value: second.value }
      result[:first_loader_still_alive] = first.alive?
      raise 'Failure control lost its live first caller' unless result[:first_loader_still_alive]

      release << true
      raise 'Failed caller did not finish' unless first.join(5)
    else
      Bootsnap.unload_cache! if result[:mode] == 'uncached'
      at_barrier = Queue.new
      second_entered = Queue.new
      first_result = Queue.new
      second_result = Queue.new
      paused = false
      observed_second = false
      result[:second_require_paths] = []
      trace = TracePoint.new(:line, :call) do |event|
        if event.event == :line && event.path == dir_path && event.lineno == 6 && Thread.current[:extension_probe_first] && !paused
          paused = true
          result[:reentrant_namespace] = mapper.get_extension_module('stdapi'.dup).name if result[:mode] == 'reentrant'
          if result[:mode] == 'reentrant' && result[:reentrant_namespace] != 'Rex::Post::Meterpreter::Extensions::Stdapi'
            raise 'Reentrant lookup returned an unexpected module'
          end

          at_barrier << snapshot.call.merge(stack: caller)
          release.pop
        elsif event.event == :call && event.method_id == :get_extension_klass && Thread.current[:extension_probe_second] && !observed_second
          observed_second = true
          second_entered << event.method_id
        elsif event.event == :call && event.method_id == :require && Thread.current[:extension_probe_second]
          value = event.binding.local_variable_get(:path) if event.binding.local_variable_defined?(:path)
          if value.to_s.include?('stdapi/stdapi')
            result[:second_require_paths] << value
          end
        end
      end
      trace.enable
      first = Thread.new do
        Thread.current[:extension_probe_first] = true
        begin
          if result[:mode] == 'module_first'
            namespace = mapper.get_extension_module('stdapi'.dup)
            klass = namespace.const_get(:Stdapi, false)
          else
            klass = mapper.get_extension_klass('stdapi'.dup)
          end
          first_result << { value: describe_class.call(klass) }
        rescue StandardError, LoadError => e
          first_result << { error: e.class.name, message: e.message, backtrace: e.backtrace }
        end
      end
      threads << first
      result[:barrier] = at_barrier.pop
      if result[:mode] == 'reentrant'
        release << true
        raise 'First loader did not finish' unless first.join(5)

        result[:first] = first_result.pop
        result[:second] = { value: describe_class.call(mapper.get_extension_klass('stdapi'.dup)) }
      else
        second = Thread.new do
          Thread.current[:extension_probe_second] = true
          begin
            second_result << { value: describe_class.call(mapper.get_extension_klass('stdapi'.dup)) }
          rescue StandardError, LoadError => e
            second_result << { error: e.class.name, message: e.message, backtrace: e.backtrace }
          end
        end
        threads << second
        result[:second_entered_lookup] = second_entered.pop
        # The first loader remains paused; this bounded join records whether the
        # second lookup escapes the in-progress load or blocks safely.
        result[:second_finished_before_release] = !second.join(0.25).nil?
        result[:while_first_paused] = snapshot.call
        release << true
        raise 'First loader did not finish' unless first.join(5)
        raise 'Second loader did not finish' unless second.join(5)

        result[:first] = first_result.pop
        result[:second] = second_result.pop
      end
    end
    result[:final] = snapshot.call
    result[:success] = result[:first] && result[:second] && !result[:first].key?(:error) && !result[:second].key?(:error)
  end
rescue StandardError, LoadError => e
  result[:probe_error] = { error: e.class.name, message: e.message, backtrace: e.backtrace }
  result[:success] = false
ensure
  release << true
  trace&.disable
  threads.select(&:alive?).each(&:kill)
  threads.each { |thread| thread.join(1) }
  result[:threads_alive_at_exit] = threads.count(&:alive?)
end

puts 'EXTENSION_LOADING_PROBE=' + JSON.generate(result)
exit(result[:success] && result[:threads_alive_at_exit].zero? ? 0 : 1)
