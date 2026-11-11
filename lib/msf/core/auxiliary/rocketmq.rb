# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Apache RocketMQ
  #
  ###
  module Auxiliary::Rocketmq
    include Msf::Exploit::Remote::Tcp
    def initialize(info = {})
      super
      register_options([ Opt::RPORT(9876) ], Msf::Auxiliary::Rocketmq)
    end

    # Sends a version request to the service, and returns the data as a list of hashes or nil on error
    #
    # @see https://github.com/Malayke/CVE-2023-33246_RocketMQ_RCE_EXPLOIT/blob/e27693a854a8e3b2863dc366f36002107e3595de/check.py#L68
    # @return [String, nil] The data as a list of hashes or nil on error.
    def send_version_request 
      data = '{"code":105,"extFields":{"Signature":"/u5P/wZUbhjanu4LM/UzEdo2u2I=","topic":"TBW102","AccessKey":"rocketmq2"},"flag":0,"language":"JAVA","opaque":1,"serializeTypeCurrentRPC":"JSON","version":401}'
      data_length = "\x00\x00\x00" + [data.length].pack('C')
      header = "\x00\x00\x00" + [data.length + data_length.length].pack('C')

      begin
        connect
        sock.send(header + data_length + data, 0)
        res_length = sock.timed_read(4)&.unpack1('N')
        return nil if res_length.nil?

        res = sock.timed_read(res_length)
      rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
        print_error("Unable to connect: #{e.class} #{e.message}")
        elog('Error sending the rocketmq version request', error: e)
        return nil
      ensure
        disconnect
      end

      if res.nil?
        vprint_error('No response received')
        return nil
      end

      unless res.include?('{')
        vprint_error('Response contains unusable data')
        return nil
      end

      res
    end

    # This function takes an ID (number) and looks through rocketmq's index of version numbers to find the real version number
    # Errors will result in "UNKNOWN_VERSION_ID_<id>" and may be caused by needing to update the version table
    # from https://github.com/apache/rocketmq/blob/develop/common/src/4d82b307ef50f5cba5717d0ebafeb3cabf336873/java/org/apache/rocketmq/common/MQVersion.java
    #
    # @param [Integer] id The version id found in the NameServer response.
    # @return [String] The Apache RocketMQ version string.
    def get_rocketmq_version(id)
      version_list = JSON.parse(File.read(::File.join(Msf::Config.data_directory, 'rocketmq_versions_list.json'), mode: 'rb'))
      version_list.fetch(id, "UNKNOWN_VERSION_ID_#{id}").gsub('_', '.')
    end

    # Decode the JSON header and optional body returned by send_version_request.
    #
    # @see https://github.com/apache/rocketmq/blob/rocketmq-all-4.9.4/remoting/src/main/java/org/apache/rocketmq/remoting/protocol/RemotingCommand.java#L141-L183
    # @param [String, nil] res Response including its serialization/header-length prefix.
    # @return [Hash, nil] Version and optional Broker data, or nil for unusable data.
    def parse_rocketmq_data(res)
      return nil unless res.is_a?(String) && res.bytesize >= 4

      # The upper byte identifies serialization; the lower 24 bits give the
      # actual header size. Error replies need not have a 95-byte header.
      prefix = res.unpack1('N')
      return nil unless (prefix >> 24).zero?

      header_size = prefix & 0x00ffffff
      return nil if header_size.zero? || header_size > res.bytesize - 4

      header = JSON.parse(res.byteslice(4, header_size))
      # The protocol's version field is a nonnegative Java int.
      return nil unless header.is_a?(Hash) && header['version'].is_a?(Integer) && header['version'].between?(0, 0x7fffffff)

      body_data = res.byteslice(4 + header_size..)
      body = body_data.empty? ? {} : JSON.parse(body_data)
      return nil unless body.is_a?(Hash)
      return nil if body['brokerDatas'] && !body['brokerDatas'].is_a?(Array)

      parsed_data = { 'version' => get_rocketmq_version(header['version']) }
      parsed_data['brokerDatas'] = body['brokerDatas'] if body['brokerDatas']
      parsed_data
    rescue JSON::ParserError => e
      vprint_error('Unable to parse RocketMQ response JSON')
      elog('Unable to parse RocketMQ response JSON', error: e)
      nil
    end

    # This function takes the broker data from the name server response, the rhost address and a default Broker port
    # number. The function searches the broker data for a broker instance listening on the rhost address and if found it
    # returns the port found. If the search is unsuccessful it returns the default broker port.
    #
    # @param [Array] broker_datas An array containing a hash of Broker info
    # @param rhost [String] The RHOST address
    # @param [Integer] default_broker_port The default broker port
    # @return [Integer] the determined broker port
    def get_broker_port(broker_datas, rhost, default_broker_port: 10911)
      # Example of brokerData:
      # [{"brokerAddrs"=>{"0"=>"172.16.199.135:10911"}, "brokerName"=>"DESKTOP-8ATHH6O", "cluster"=>"DefaultCluster"}]

      if broker_datas['brokerDatas'].blank?
        print_status("brokerDatas field is missing from the response, assuming default broker port of #{default_broker_port}")
        return default_broker_port
      end
      broker_datas['brokerDatas'].each do |broker_data|
        if broker_data['brokerAddrs'].blank?
          print_status("brokerAddrs field is missing from the response, assuming default broker port of #{default_broker_port}")
          return default_broker_port
        end
        broker_data['brokerAddrs'].values.each do |broker_endpoint|
          next unless broker_endpoint.start_with?("#{rhost}:")
          return broker_endpoint.match(/\A#{rhost}:(\d+)\z/)[1].to_i
        end
      end

      print_status("autodetection failed, assuming default port of #{default_broker_port}")
      default_broker_port
    end
  end
end
