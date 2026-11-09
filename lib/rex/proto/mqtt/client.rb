# -*- coding: binary -*-

require 'mqtt'

##
# MQTT protocol support
##

module Rex
  module Proto
    module MQTT
      class Client

        def initialize(sock, opts = {})
          @sock = sock
          @opts = opts
        end

        # @return [::MQTT::Packet::Connack] The broker's accepted or refused connection reply.
        # @raise [Rex::ConnectionError] If the broker does not return a complete CONNACK.
        def connect
          connect_opts = {
            client_id: @opts[:client_id]
          }

          unless @opts[:username].blank?
            connect_opts[:username] = @opts[:username]
          end
          unless @opts[:password].blank?
            connect_opts[:password] = @opts[:password]
          end
          connect = ::MQTT::Packet::Connect.new(connect_opts).to_s
          @sock.put(connect)
          res = @sock.get_once(-1, @opts[:read_timeout])
          raise Rex::ConnectionError.new(reason: 'MQTT CONNECT did not receive a response') if res.nil? || res.empty?

          packet = ::MQTT::Packet.parse(res)
          # The gem accepts a one-byte CONNACK with a nil return code. Require
          # its complete two-byte variable header before callers consume it.
          unless packet.is_a?(::MQTT::Packet::Connack) && packet.body_length == 2
            raise Rex::ConnectionError.new(reason: 'MQTT CONNECT expected a CONNACK with a two-byte body')
          end

          packet
        rescue ::MQTT::ProtocolException => e
          raise Rex::ConnectionError.new(reason: "MQTT CONNECT received an invalid response: #{e.message}")
        end

        def connect?
          connect.return_code.zero?
        end

        def disconnect
          disconnect = ::MQTT::Packet::Disconnect.new().to_s
          @sock.put(disconnect)
        end
      end
    end
  end
end
