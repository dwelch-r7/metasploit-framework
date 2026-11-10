# frozen_string_literal: true

require 'json'
require 'base64'

# Records actual returned producer strings without regenerating/serializing a
# payload. These are RETURNED-XML/URI observations, not socket or PCAP evidence.
module GeoServerInputs
  RCE = 'exploit/multi/http/geoserver_unauth_rce_cve_2024_36401'
  XXE = 'auxiliary/gather/geoserver_wms_getmap_xxe_file_read'

  def self.path
    File.join(File.dirname(Msf::Config.config_directory), 'geoserver-returned-inputs.jsonl')
  end

  def self.record(owner, kind, values)
    File.open(path, 'a') { |file| file.puts(JSON.generate(values.merge(owner: owner.fullname, kind: kind))) }
  end

  # Captures the single string returned by the owning command producer.
  module RceProducer
    def create_payload(command, feature_type)
      super.tap { |returned| GeoServerInputs.record(self, 'RETURNED-XML', arguments: [command, feature_type], returned_base64: Base64.strict_encode64(returned.b)) }
    end
  end

  # Preserves every owning random choice while retaining its returned bytes.
  module XxeProducer
    def build_xxe_payload(path)
      super.tap { |returned| GeoServerInputs.record(self, 'RETURNED-XML', arguments: [path], returned_base64: Base64.strict_encode64(returned.b)) }
    end

    def build_wms_uri
      super.tap { |returned| GeoServerInputs.record(self, 'RETURNED-URI', arguments: [], returned_base64: Base64.strict_encode64(returned.b)) }
    end
  end

  # Captures public API arguments and responses without HTTP serialization.
  module Requests
    def send_request_cgi(options = {}, *arguments, **keywords)
      # These are the real public request arguments and returned body, not a
      # reconstruction of serialized/socket bytes. Delegate exactly once.
      values = {
        host: rhost, port: rport, method: options['method'], uri: options['uri'],
        vars_get: options['vars_get'], data_base64: options['data'] && Base64.strict_encode64(options['data'].b)
      }
      super.tap do |response|
        GeoServerInputs.record(self, 'REQUEST-ARGS/RESPONSE-BODY', values.merge(status: response&.code, body_base64: response && Base64.strict_encode64(response.body.b)))
      end
    end
  end

  def self.install(framework)
    File.write(path, '')
    rce = framework.modules.create(RCE)
    rce.datastore['TARGET'] = 0
    rce.class.prepend(RceProducer) unless rce.class.ancestors.include?(RceProducer)
    xxe = framework.modules.create(XXE)
    xxe.class.prepend(XxeProducer) unless xxe.class.ancestors.include?(XxeProducer)
    [rce, xxe].each { |owner| owner.class.prepend(Requests) unless owner.class.ancestors.include?(Requests) }
    { target_name: rce.target.name, generic_compatible: rce.compatible_payloads.map(&:first).include?('cmd/unix/generic') }
  end
end
