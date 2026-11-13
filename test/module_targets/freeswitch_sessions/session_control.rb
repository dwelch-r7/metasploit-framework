# frozen_string_literal: true

require_relative '../druid_sessions/session_control'
require_relative '../rocketmq_sessions/session_control'
require_relative '../saltstack_deployer/session_control'
require_relative '../log4shell_execution/session_control'

# Reuse public session/generation APIs; no owner or encoder method is replaced.
module FreeSwitchExecutionControl
  def self.constraints(handler, framework, target)
    owner = framework.modules.create('exploit/multi/misc/freeswitch_event_socket_cmd_exec')
    owner.datastore['TARGET'] = target
    handler.payload_info['BadChars'] = owner.payload_badchars
    { badchars: handler.payload_badchars.bytes, target: target }
  end

  def self.generated(job, expected, framework)
    if expected.start_with?('linux/')
      SaltDeploymentSessionControl.executable(job, expected, framework)
    else
      RocketmqSessionControl.command(job, expected)
    end
  end

  def self.owner_executable(framework, identifier)
    owner = framework.sessions.fetch(identifier).exploit
    bytes = owner.exe
    raise ArgumentError, 'Owning stager has no generated ELF' unless bytes&.start_with?("\x7fELF".b)

    { sha256: Digest::SHA256.hexdigest(bytes), bytes: bytes.bytesize, elf_class: bytes.getbyte(4), machine: bytes.byteslice(18, 2).unpack1('v'), commands: owner.cmd_list }
  end

  def self.proof(framework, identifier, path, value)
    session = framework.sessions.fetch(identifier)
    Log4shellSessionControl.proof(framework, identifier, path, value).merge(via_exploit: session.via_exploit, via_payload: session.via_payload)
  end

  def self.close(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      session.core.shutdown
    elsif session.via_payload.include?('reverse_perl')
      # Perl launches a child shell per command. Transport EOF ends its own
      # interpreter; an exit command would end only the disposable child.
      session.shell_close
    else
      Log4shellSessionControl.shutdown(framework, identifier)
    end
    framework.sessions[identifier]&.shell_close if session.type == 'shell'
    framework.sessions[identifier]&.kill
    { id: identifier, public_close_requested: true }
  end
end
