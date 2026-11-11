# frozen_string_literal: true

require 'base64'
require_relative '../ntp/report_observer'

# Retain genuine complete vendor replies without replacing transport or parsing.
module ModuleTargetRmiObservations
  include ModuleTargetNtpReports

  def safe_get_once(nsock = sock, loop_timeout = read_loop_timeout)
    value = super
    File.open(File.join(Msf::Config.config_directory, 'rmi-wire.jsonl'), 'a') do |file|
      file.puts(JSON.generate(module: fullname, host: nsock.peerhost, port: nsock.peerport,
                              bytes: value&.bytesize, base64: value && Base64.strict_encode64(value)))
    end
    value
  end
end
