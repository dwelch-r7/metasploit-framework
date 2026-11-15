# frozen_string_literal: true

module ErlangSshSettings
  OWNER = 'exploit/linux/ssh/ssh_erlangotp_rce'
  PAYLOADS = ['cmd/linux/https/x64/meterpreter/reverse_tcp', 'cmd/unix/reverse_bash'].freeze
end
