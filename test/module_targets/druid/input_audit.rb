# frozen_string_literal: true

require 'base64'
require 'json'

# Records executing-instance inputs without regenerating a payload or changing
# its command. Every production method continues through its ordinary super.
module DruidTargetInputAudit
  def check
    DruidTargetInputs.record(self, 'check')
    super
  end

  def exploit
    DruidTargetInputs.record(self, 'exploit')
    super
  end
end

# Applied only to the owner that already defines execute_command, preserving
# the other module's public method set and payload compatibility surface.
module DruidTargetCommandAudit
  def execute_command(command, opts = {})
    DruidTargetInputs.record(self, 'execute_command', command)
    super
  end
end

# Captures the actual serializer command argument without calling encoded again.
module DruidTargetSerializedCommandAudit
  def generate_java_deserialization_for_command(name, shell, command)
    DruidTargetInputs.record(self, 'java_command', command)
    super
  end
end

# Test-local configuration through ordinary Framework module/datastore APIs.
module DruidTargetInputs
  OWNERS = %w[exploit/linux/http/apache_druid_js_rce exploit/multi/http/apache_druid_cve_2023_25194].freeze

  def self.record(instance, kind, command = nil)
    row = {
      kind: kind, object_id: instance.object_id, fullname: instance.fullname,
      target_index: instance.target_index, target_name: instance.target&.name,
      payload: instance.datastore['PAYLOAD'], rhost: instance.datastore['RHOST'], rhosts: instance.datastore['RHOSTS'], rport: instance.datastore['RPORT'], target_uri: instance.datastore['TARGETURI'],
      command_base64: instance.datastore['CMD'] && Base64.strict_encode64(instance.datastore['CMD'].b),
      argument_base64: command && Base64.strict_encode64(command.b),
      srvhost: instance.srvhost, lhost: instance.datastore['LHOST'], callback_host: instance.srvhost_addr
    }
    path = File.join(File.dirname(Msf::Config.config_directory), 'executing-inputs.jsonl')
    File.open(path, 'a') { |output| output.puts(JSON.generate(row)) }
  end

  def self.install(framework, address)
    # SocketServer intentionally gives LHOST precedence over SRVHOST.
    framework.datastore['LHOST'] = address
    catalog = OWNERS.to_h do |name|
      instance = framework.modules.create(name)
      raise "Could not load #{name}" unless instance

      targets = instance.targets.each_with_index.map { |target, index| { index: index, name: target.name, arch: target.arch, platform: target.platform&.platforms&.map(&:realname) } }
      command_target = targets.find { |target| target[:name] == 'Linux' || target[:name] == 'Unix (in-memory)' }
      raise "Command target is absent for #{name}" unless command_target

      instance.datastore['TARGET'] = command_target.fetch(:index)
      instance.datastore['SRVHOST'] = address
      compatible = instance.compatible_payloads.map(&:first).include?('cmd/unix/generic')
      raise "Generic command is incompatible with #{name}/#{instance.target.name}" unless compatible
      raise "Unexpected callback address: #{instance.srvhost_addr}" unless instance.srvhost_addr == address

      instance.class.prepend(DruidTargetInputAudit) unless instance.class.ancestors.include?(DruidTargetInputAudit)
      if name == 'exploit/linux/http/apache_druid_js_rce' && !instance.class.ancestors.include?(DruidTargetCommandAudit)
        instance.class.prepend(DruidTargetCommandAudit)
      end
      if name == 'exploit/multi/http/apache_druid_cve_2023_25194' && !instance.class.ancestors.include?(DruidTargetSerializedCommandAudit)
        instance.class.prepend(DruidTargetSerializedCommandAudit)
      end
      [name, { targets: targets, command_target: command_target.fetch(:index), command_target_name: instance.target.name, generic_in_compatible_list: compatible, callback_host: instance.srvhost_addr }]
    end
    File.write(File.join(File.dirname(Msf::Config.config_directory), 'input-audit-installed.json'), JSON.pretty_generate(catalog))
    catalog
  end
end
