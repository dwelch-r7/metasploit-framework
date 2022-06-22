module Rex::Proto::Kerberos

  class Helper

    def self.parse_int_32(input)
      input.value[0].value.to_i
    end

    def self.encode_int_32(input)
      bn = OpenSSL::BN.new(input.to_s)
      OpenSSL::ASN1::Integer.new(bn)
    end


    def self.parse_octet_string(input)
      input.value[0].value
    end

    def self.encode_octet_string(input)
      OpenSSL::ASN1::OctetString.new(input)
    end

    def self.decode_ticket_flags(input)
      Rex::Proto::Kerberos::Model::TicketFlags.new(input.value[0].value.unpack1('N'))
    end

    def self.encode_ticket_flags(input)
      OpenSSL::ASN1::BitString.new([input.value].pack('N'))
    end

    def self.decode_encryption_key(input)
      Rex::Proto::Kerberos::Model::EncryptionKey.decode(input.value[0])
    end

    def self.encode_encryption_key(input)
      input.encode
    end

    def self.decode_realm(input)
      input.value[0].value
    end

    def self.encode_realm(input)
      OpenSSL::ASN1::GeneralString.new(input)
    end

    def self.decode_principal_name(input)
      Rex::Proto::Kerberos::Model::PrincipalName.decode(input.value[0])
    end

    def self.encode_principal_name(input)
      input.encode
    end

    def self.decode_transited_encoding(input)
      Rex::Proto::Kerberos::Model::TransitedEncoding.decode(input.value[0])
    end

    def self.encode_transited_encoding(input)
      input.encode
    end

    def self.decode_kerberos_time(input)
      input.value[0].value
    end

    def self.encode_kerberos_time(input)
      OpenSSL::ASN1::GeneralizedTime.new(input)
    end

    def self.decode_host_address(input)
      Rex::Proto::Kerberos::Model::HostAddress.decode(input)
    end

    def self.encode_host_address(input)
      input.encode
    end

    def self.decode_authorization_data(input)
      Rex::Proto::Kerberos::Model::AuthorizationData.decode(input)
    end

    def self.encode_authorization_data(input)
      input.encode
    end
  end
end
