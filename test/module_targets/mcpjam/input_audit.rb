# frozen_string_literal: true

require 'base64'
require 'json'

# Observe production dispatch and cleanup without replacing target operations.
module MCPJamTargetAudit
  def check
    result = super
    MCPJamTargetInputs.record(self, kind: 'check-return', code: result.code, reason: result.reason)
    result
  rescue StandardError => e
    MCPJamTargetInputs.record(self, kind: 'check-raise', error: e.class.name, message: e.message)
    raise
  end

  def execute_command(command, opts = {})
    MCPJamTargetInputs.record(self, kind: 'execute-command', command_base64: Base64.strict_encode64(command.b))
    super
  end

  def cleanup_mcp_server(id)
    MCPJamTargetInputs.record(self, kind: 'cleanup', id: id)
    super
  end

  def send_request_cgi(*arguments, **keywords)
    response = super
    options = arguments.first || keywords
    data = options['data']
    MCPJamTargetInputs.record(
      self,
      kind: 'http', method: options.fetch('method', 'GET'), uri: options['uri'], status: response&.code,
      data_base64: data && Base64.strict_encode64(data.b), data_encoding: data&.encoding&.name, data_length: data&.length, data_bytesize: data&.bytesize,
      response_base64: response && Base64.strict_encode64(response.body.to_s.b)
    )
    response
  end
end

# Install the observer only on the actual loaded owner class.
module MCPJamTargetInputs
  OWNER = 'exploit/multi/http/mcpjam_inspector_rce'

  def self.record(instance, **value)
    path = File.join(File.dirname(Msf::Config.config_directory), 'mcpjam-owner-calls.jsonl')
    row = value.merge(object_id: instance.object_id, method_option: instance.datastore['EXEC_METHOD'], fetch_output: instance.datastore['FETCH_OUTPUT'], server_id: instance.datastore['SERVER_ID'])
    row = row.transform_values do |item|
      next item unless item.is_a?(String)

      text = item.dup.force_encoding(Encoding::UTF_8)
      text.valid_encoding? ? text : { bytes_base64: Base64.strict_encode64(item.b) }
    end
    File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
  end

  def self.install(framework)
    instance = framework.modules.create(OWNER)
    raise "Could not load #{OWNER}" unless instance

    instance.class.prepend(MCPJamTargetAudit) unless instance.class.ancestors.include?(MCPJamTargetAudit)
    OWNER
  end
end
