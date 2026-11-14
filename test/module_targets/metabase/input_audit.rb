# frozen_string_literal: true

require 'base64'
require 'json'

# Observe the real owner without replacing its requests or execution paths.
module MetabaseTargetAudit
  def check
    result = super
    MetabaseTargetInputs.record(self, kind: 'check-return', code: result.code, reason: result.reason)
    result
  rescue StandardError => e
    MetabaseTargetInputs.record(self, kind: 'check-raise', error: e.class.name, message: e.message)
    raise
  end

  def send_request_cgi(*arguments, **keywords)
    response = super
    options = arguments.first || keywords
    data = options['data']
    MetabaseTargetInputs.record(
      self,
      kind: 'http', method: options.fetch('method', 'GET'), uri: options['uri'], status: response&.code,
      data_base64: data && Base64.strict_encode64(data.b), data_length: data&.length, data_bytesize: data&.bytesize,
      response_base64: response && Base64.strict_encode64(response.body.to_s.b)
    )
    response
  end
end

# Attach the observer only to the actual loaded production owner class.
module MetabaseTargetInputs
  OWNER = 'exploit/linux/http/metabase_setup_token_rce'

  def self.record(instance, **values)
    path = File.join(File.dirname(Msf::Config.config_directory), 'metabase-owner-calls.jsonl')
    row = values.merge(object_id: instance.object_id, target_uri: instance.datastore['TARGETURI'], port: instance.datastore['RPORT'])
    row = row.transform_values do |value|
      next value unless value.is_a?(String)

      text = value.dup.force_encoding(::Encoding::UTF_8)
      text.valid_encoding? ? text : { bytes_base64: Base64.strict_encode64(value.b) }
    end
    File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
  end

  def self.install(framework)
    instance = framework.modules.create(OWNER)
    raise "Could not load #{OWNER}" unless instance

    instance.class.prepend(MetabaseTargetAudit) unless instance.class.ancestors.include?(MetabaseTargetAudit)
    OWNER
  end
end
