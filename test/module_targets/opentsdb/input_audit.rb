# frozen_string_literal: true

require 'base64'
require 'json'

# Observe the actual command argument on the executing replicant, preserving
# payload generation, request bytes, return values and exception behavior.
module OpenTsdbCommandAudit
  def execute_command(command, opts = {})
    record = { fullname: fullname, command: Base64.strict_encode64(command.b), datastore_command: datastore['CMD'] && Base64.strict_encode64(datastore['CMD'].b), target: target.name, payload: datastore['PAYLOAD'] }
    path = File.join(File.dirname(Msf::Config.config_directory), 'opentsdb-executing-inputs.jsonl')
    File.open(path, 'a') { |output| output.puts(JSON.generate(record)) }
    super
  end
end

# Installs read-only command observations through the ordinary module catalog.
module OpenTsdbInputs
  OWNERS = %w[exploit/linux/http/opentsdb_yrange_cmd_injection exploit/linux/http/opentsdb_key_cmd_injection].freeze

  def self.install(framework, address)
    framework.datastore['LHOST'] = address
    OWNERS.to_h do |name|
      instance = framework.modules.create(name)
      raise "Could not load #{name}" unless instance

      instance.class.prepend(OpenTsdbCommandAudit) unless instance.class.ancestors.include?(OpenTsdbCommandAudit)
      targets = instance.targets.each_with_index.map { |target, index| { index: index, name: target.name, arch: target.arch } }
      [name, { targets: targets, default_payload: instance.datastore['PAYLOAD'] }]
    end
  end
end
