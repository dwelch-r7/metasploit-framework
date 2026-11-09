# -*- coding: binary -*-


module Msf
  module Auxiliary::Etcd
    TCP_PORT = 2379
    def initialize(info = {})
      super

      register_options(
        [
          Opt::RPORT(TCP_PORT),
          OptString.new('TARGETURI', [true, 'base URI of etcd', '/'])
        ]
      )

      register_autofilter_ports([TCP_PORT])
    end

    # Identify the version document before reporting an etcd service.
    # @param target_uri [String] Base path of the etcd API
    # @return [Hash, nil] Validated version fields, or nil when not identified
    def fingerprint_service(target_uri)
      res = send_request_raw(
        'uri'    => normalize_uri(target_uri, 'version'),
        'method' => 'GET'
      )
      if res && res.code == 200
        begin
          banner = res.get_json_document
        rescue JSON::ParserError => e
          print_error("Failed to read JSON from etcd version response: #{e.class} - #{e.message}}")
          return
        end
      elsif res
        vprint_error("Invalid response #{res.code} for etcd version response")
        return
      else
        vprint_error("No response for etcd version probe")
        return
      end

      unless banner.is_a?(Hash) && %w[etcdserver etcdcluster].all? { |field| banner[field].is_a?(String) && banner[field].match?(/\A\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\z/) }
        vprint_error('Version response does not identify etcd server and cluster versions')
        return
      end

      report_service(
        host: rhost,
        port: rport,
        name: 'etcd',
        proto: 'tcp',
        info: banner
      )
      banner
    end
  end
end
