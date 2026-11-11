# frozen_string_literal: true

require 'base64'
require 'digest'

# Record real successful TCP connections without changing destination or bytes.
module RocketmqSessionConnections
  def connect(*arguments)
    connection = super
    File.open(File.join(Msf::Config.config_directory, 'rocketmq-connections.jsonl'), 'a') do |file|
      file.puts(JSON.generate(host: connection.peerhost, port: connection.peerport))
    end
    connection
  end

  def on_new_session(session)
    result = super
    File.open(File.join(Msf::Config.config_directory, 'rocketmq-callbacks.jsonl'), 'a') do |file|
      file.puts(JSON.generate(session: session.sid, type: session.type, session_count: session_count, successful: successful))
    end
    result
  end
end

# Use the ordinary handler's already generated command; never generate another
# payload or replace its encoding after the handler/listener has started.
module RocketmqSessionControl
  def self.constraints(handler, framework)
    owner = framework.modules.create('exploit/multi/http/apache_rocketmq_update_config')
    # Exercise the handler's normal encoder with the real exploit requirement.
    # Changing this instance's metadata does not override a production method.
    handler.payload_info['BadChars'] = owner.payload_badchars
    { badchars: handler.payload_badchars.bytes }
  end

  def self.command(job, expected)
    handler, payload = job.ctx
    raise ArgumentError, 'Unexpected handler context' unless handler.fullname == 'exploit/multi/handler' && payload.refname == expected && handler.payload_instance.equal?(payload)

    value = handler.payload.encoded
    raise ArgumentError, 'Handler has no generated command' unless value.is_a?(String) && !value.empty?

    { payload: payload.refname, command_base64: Base64.strict_encode64(value), sha256: Digest::SHA256.hexdigest(value) }
  end

  def self.proof(framework, identifier, path)
    raise ArgumentError, 'Unexpected proof path' unless path.match?(%r{\A/tmp/module-target-rocketmq-proof-[a-f0-9]+\z})

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
      file = session.fs.file.new(path, 'wb')
      begin
        file.write('rocketmq-session')
      ensure
        file.close
      end
      { id: identifier, type: session.type, pid: pid, identity: identity }
    elsif session.type == 'shell'
      output = session.shell_command_token("printf %s rocketmq-session > #{path}; id; echo $$")
      pid = output.to_s.lines.map(&:strip).reverse.find { |line| line.match?(/\A\d+\z/) }
      raise "Remote shell did not return a PID: #{output.inspect}" unless pid

      { id: identifier, type: session.type, pid: pid.to_i, identity: output }
    else
      raise ArgumentError, "Unsupported session: #{session.type}"
    end
  end
end
