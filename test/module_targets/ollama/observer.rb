# frozen_string_literal: true

require 'base64'

# Retain real HTTP responses while leaving the client and vendor handlers intact.
module ModuleTargetOllamaHttp
  def send_request_cgi(*args)
    opts = args.first || {}
    response = super
    File.open(File.join(Msf::Config.config_directory, 'ollama-http.jsonl'), 'a') do |file|
      file.puts(JSON.generate(
        method: opts.fetch('method', 'GET'), uri: opts['uri'], data: opts['data'],
        code: response&.code, body_base64: response && Base64.strict_encode64(response.body.to_s)
      ))
    end
    response
  end
end
