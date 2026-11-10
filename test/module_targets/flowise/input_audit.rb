# frozen_string_literal: true

require 'json'
require 'base64'

# Passive selected-owner API observations, never reconstructed wire/PCAP.
module FlowiseInputs
  CUSTOM = 'exploit/multi/http/flowise_custommcp_rce'
  JS = 'exploit/multi/http/flowise_js_rce'
  MCP = 'exploit/multi/http/flowise_mcp_rce'
  ATO = 'auxiliary/admin/http/flowise_auth_bypass_cve_2025_58434'
  OWNERS = [CUSTOM, JS, MCP, ATO].freeze

  def self.path
    File.join(File.dirname(Msf::Config.config_directory), 'flowise-inputs.jsonl')
  end

  def self.bytes(value)
    Base64.strict_encode64(value.b) if value.is_a?(String)
  end

  def self.record(owner, kind, values)
    File.open(path, 'a') { |file| file.puts(JSON.generate(values.merge(owner: owner.fullname, kind: kind))) }
  end

  # Observe public HTTP arguments and actual returned peer bodies.
  module Requests
    def send_request_cgi(options = {}, *arguments, **keywords)
      values = {
        host: rhost, port: rport, method: options['method'], uri: options['uri'],
        headers: options['headers'], data_base64: FlowiseInputs.bytes(options['data'])
      }
      super.tap do |response|
        FlowiseInputs.record(self, 'REQUEST-ARGS/RESPONSE-BODY', values.merge(status: response&.code, body_base64: response && FlowiseInputs.bytes(response.body)))
      end
    end
  end

  # Capture the existing encoded command argument, without regeneration.
  module Commands
    def execute_command(command, *arguments, **keywords)
      FlowiseInputs.record(self, 'COMMAND-ARG', command_base64: FlowiseInputs.bytes(command))
      super
    end
  end

  # Retain the exact produced tar and HTTP callback arguments.
  module Archive
    def create_tar_package
      super.tap { |returned| FlowiseInputs.record(self, 'RETURNED-TAR', returned_base64: FlowiseInputs.bytes(returned)) }
    end

    def on_request_uri(client, request)
      FlowiseInputs.record(self, 'HTTP-REQUEST', peer: client.peerhost, connection: client.object_id, method: request.method, uri: request.uri)
      super
    end

    def send_response(client, body = '', *arguments, **keywords)
      FlowiseInputs.record(self, 'RESPONSE-ARGS', peer: client.peerhost, connection: client.object_id, body_base64: FlowiseInputs.bytes(body))
      super
    end
  end

  def self.install(framework, selected = OWNERS)
    raise ArgumentError, 'Unknown observer owner' unless (selected - OWNERS).empty?

    File.write(path, '')

    selected.to_h do |name|
      owner = framework.modules.create(name)
      raise "Missing selected owner #{name}" unless owner
      raise "Unexpected observer owner for #{name}" unless owner.fullname == name

      owner.class.prepend(Requests) unless owner.class.ancestors.include?(Requests)
      if [CUSTOM, JS].include?(name)
        owner.class.prepend(Commands) unless owner.class.ancestors.include?(Commands)
      elsif name == MCP
        owner.class.prepend(Archive) unless owner.class.ancestors.include?(Archive)
      end
      payloads = name == ATO ? [] : owner.compatible_payloads.map(&:first)
      [name, name == ATO ? {} : { target_name: owner.targets.first.name, generic_compatible: payloads.include?('cmd/unix/generic'), fetch_compatible: payloads.include?('cmd/linux/http/x64/meterpreter_reverse_tcp'), python_compatible: payloads.include?('cmd/unix/reverse_python') }]
    end
  end
end
