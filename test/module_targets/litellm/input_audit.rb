# frozen_string_literal: true

require 'base64'
require 'json'

# Observe actual owner calls; every production operation continues through super.
module LiteLLMTargetAudit
  def check_host(ip)
    result = super
    LiteLLMTargetInputs.record(self, kind: 'check-return', code: result.code, reason: result.reason)
    result
  rescue StandardError => e
    LiteLLMTargetInputs.record(self, kind: 'check-raise', error: e.class.name, message: e.message)
    raise
  end

  def send_request_cgi(*arguments, **keywords)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = super
    options = arguments.fetch(0, {})
    data = options['data']
    LiteLLMTargetInputs.record(
      self,
      kind: 'http', method: options.fetch('method', 'GET'), uri: options['uri'],
      authorization: options.dig('headers', 'Authorization'), data_base64: data && Base64.strict_encode64(data.b),
      data_encoding: data&.encoding&.name, data_length: data&.length, data_bytesize: data&.bytesize,
      status: response&.code, seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    )
    response
  end
end

# Install the observer only on the actual registered scanner owner.
module LiteLLMTargetInputs
  OWNER = 'auxiliary/scanner/http/litellm_proxy_sqli'

  def self.record(instance, **value)
    path = File.join(File.dirname(Msf::Config.config_directory), 'litellm-owner-calls.jsonl')
    File.open(path, 'a') { |stream| stream.puts(JSON.generate(value.merge(object_id: instance.object_id, model: instance.datastore['MODEL'], delay: instance.datastore['SqliDelay']))) }
  end

  def self.install(framework)
    owner = framework.modules.create(OWNER)
    raise "Could not load #{OWNER}" unless owner

    owner.class.prepend(LiteLLMTargetAudit) unless owner.class.ancestors.include?(LiteLLMTargetAudit)
    OWNER
  end
end
