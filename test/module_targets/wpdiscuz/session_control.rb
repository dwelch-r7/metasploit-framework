# frozen_string_literal: true

require 'base64'
require 'digest'
require_relative 'profiles'
require_relative '../druid_sessions/session_control'

# Observes effective per-run state without changing any module methods.
class WpDiscuzRunObserver
  include Msf::GeneralEventSubscriber
  attr_reader :current

  def initialize(path)
    @path = path
  end

  def on_module_run(instance)
    return unless instance.fullname == WpDiscuzProfiles::OWNER

    @current = instance
    row = { owner: instance.fullname, object_id: instance.object_id, options: instance.datastore.to_h.slice(*%w[PAYLOAD CMD BLOGPATH TARGETURI RHOST RHOSTS RPORT LHOST LPORT AutoCheck]), exploit_source: instance.method(:exploit).source_location, metadata_source: instance.method(:upload_metadata).source_location, owner_sha256: Digest::SHA256.file('modules/exploits/unix/webapp/wp_wpdiscuz_unauthenticated_file_upload.rb').hexdigest }
    File.open(@path, 'a') { |file| file.puts(JSON.generate(row)) }
  end
end

# Real handler and public session APIs; no HTTP or session doubles.
module WpDiscuzSessionControl
  def self.install(framework)
    observation = DruidSessionControl.install(framework)
    path = File.join(File.dirname(Msf::Config.config_directory), 'effective-run-options.jsonl')
    File.write(path, '')
    observer = WpDiscuzRunObserver.new(path)
    framework.events.add_general_subscriber(observer)
    framework.instance_variable_set(:@wpdiscuz_run_observer, observer)
    observation.merge(effective_run_options_path: path)
  end

  def self.cached_php(job, expected)
    raise ArgumentError, 'Unexpected calibration payload' unless WpDiscuzProfiles::PROFILES.fetch('wpdiscuz').fetch('payloads').include?(expected)

    handler, payload = job.ctx
    raise ArgumentError, 'Unexpected calibration handler' unless handler.fullname == 'exploit/multi/handler' && payload.refname == expected && handler.payload_instance.equal?(payload)

    bytes = handler.payload.encoded
    raise ArgumentError, 'Missing cached PHP payload' unless bytes.is_a?(String) && !bytes.empty?

    { payload: payload.refname, bytes_base64: Base64.strict_encode64(bytes), sha256: Digest::SHA256.hexdigest(bytes) }
  end

  def self.proof(framework, identifier, path, marker)
    raise ArgumentError, 'Unexpected lab proof path' unless path.match?(%r{\A/tmp/module-target-wpdiscuz-proofs/[a-z0-9_-]+\z})
    raise ArgumentError, 'Unexpected lab marker' unless marker.match?(/\Awpdiscuz_[a-z0-9_]+\z/)

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
      handle = session.fs.file.new(path, 'wb')
      begin
        written = handle.write(marker)
      ensure
        handle.close
      end
      raise IOError, 'Remote proof write was incomplete' unless written == marker.bytesize
    elsif session.type == 'shell'
      identity = session.shell_command_token("printf %s #{marker} > #{path};printf '\\nWPDISCUZ_PID=%s UID=%s\\n' $$ $(id -u)")
      pid = identity.to_s[/^WPDISCUZ_PID=(\d+) UID=33\r?$/, 1]
      raise IOError, 'Remote shell did not return its PID and account' unless pid
    else
      raise ArgumentError, "Unsupported session type #{session.type}"
    end
    { id: identifier, type: session.type, owner: session.via_exploit, payload: session.via_payload, pid: pid.to_i, identity: identity, peer: session.tunnel_peer }
  end
end
