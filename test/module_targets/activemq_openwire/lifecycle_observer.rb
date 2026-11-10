# frozen_string_literal: true

# Read-only observations of real services; no response or cleanup
# behavior is replaced. This is loaded only by the isolated acceptance console.
module ModuleTargetActiveMqLifecycle
  def self.snapshot(server)
    return nil unless server

    {
      id: server.object_id, class: server.class.name, port: server.listen_port,
      references: server.instance_variable_get(:@_references), resources: server.resources.keys,
      context_owner: server.context['MsfExploit']&.fullname,
      managed: Rex::ServiceManager.instance.values.include?(server)
    }
  end

  def self.services
    Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).map { |server| snapshot(server) }
  end

  def self.record(record)
    path = File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'activemq-lifecycle.jsonl')
    File.open(path, 'a') { |file| file.puts(JSON.generate(record.merge(monotonic: Process.clock_gettime(Process::CLOCK_MONOTONIC)))) }
  end

  def cleanup
    fetch = payload_instance&.instance_variable_get(:@fetch_service)
    callback = service
    owned = payload_instance&.instance_variable_get(:@myresources)
    super
  ensure
    # Perform serialization and file I/O only after production cleanup, so these
    # observations cannot keep the XML listener open during a callback race.
    ModuleTargetActiveMqLifecycle.record(
      event: 'cleanup', payload: payload_instance&.fullname, handler_enabled: handler_enabled?,
      owned_fetch_resources: owned, fetch: ModuleTargetActiveMqLifecycle.snapshot(fetch),
      callback: ModuleTargetActiveMqLifecycle.snapshot(callback)
    )
  end
end
