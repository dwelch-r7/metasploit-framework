# frozen_string_literal: true

require 'base64'
require_relative '../ntp/report_observer'

# Observe the actual production helper's return without replacing its transport.
module ModuleTargetRocketmqObservations
  include ModuleTargetNtpReports

  def send_version_request
    response = super
    File.open(File.join(Msf::Config.config_directory, 'rocketmq-wire.jsonl'), 'a') do |file|
      file.puts(JSON.generate(module: fullname, host: rhost, port: rport,
                              bytes: response&.bytesize, base64: response && Base64.strict_encode64(response)))
    end
    response
  end
end
