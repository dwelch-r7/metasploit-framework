# -*- coding: binary -*-

module Rex::Proto::Kerberos::Model
  # This class provides a representation of a Kerberos ticket encrypted part that helps
  # a client authenticate to a service.
  class TicketEncPart < Element

    attr_accessor :flags              # [0] TicketFlags,
    attr_accessor :key                # [1] EncryptionKey,
    attr_accessor :crealm             # [2] Realm,
    attr_accessor :cname              # [3] PrincipalName,
    attr_accessor :transited          # [4] TransitedEncoding,
    attr_accessor :authtime           # [5] KerberosTime,
    attr_accessor :starttime          # [6] KerberosTime OPTIONAL,
    attr_accessor :endtime            # [7] KerberosTime,
    attr_accessor :renew_till         # [8] KerberosTime OPTIONAL,
    attr_accessor :caddr              # [9] HostAddresses OPTIONAL,
    attr_accessor :authorization_data # [10] AuthorizationData OPTIONAL


    # Decodes the Rex::Proto::Kerberos::Model::TicketEncPart from an input
    #
    # @param input [String, OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [self] if decoding succeeds
    # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
    def decode(input)
      case input
      when String
        decode_string(input)
      when OpenSSL::ASN1::ASN1Data
        decode_asn1(input)
      else
        raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode TicketEncPart, invalid input'
      end

      self
    end

    # Encodes a Rex::Proto::Kerberos::Model::TicketEncPart into an ASN.1 String
    #
    # @return [String]
    def encode
      to_asn1.to_der
    end


    # Encodes a Rex::Proto::Kerberos::Model::TicketEncPart into ASN.1
    #
    # @return [OpenSSL::ASN1::ASN1Data] The TicketEncPart ASN1Data
    def to_asn1
      elems = []
      elems << OpenSSL::ASN1::ASN1Data.new([encode_flags], 0, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_key], 1, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_crealm], 2, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_cname], 3, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_transited], 4, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_authtime], 5, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_starttime], 6, :CONTEXT_SPECIFIC) if starttime
      elems << OpenSSL::ASN1::ASN1Data.new([encode_endtime], 7, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_renew_till], 8, :CONTEXT_SPECIFIC) if renew_till
      elems << OpenSSL::ASN1::ASN1Data.new([encode_caddr], 9, :CONTEXT_SPECIFIC) if caddr
      elems << OpenSSL::ASN1::ASN1Data.new([encode_authorization_data], 10, :CONTEXT_SPECIFIC) if authorization_data

      seq = OpenSSL::ASN1::Sequence.new(elems)
      OpenSSL::ASN1::ASN1Data.new([seq], 3, :APPLICATION)
    end

    private

    # Decodes a Rex::Proto::Kerberos::Model::TicketEncPart from an String
    #
    # @param input [String] the input to decode from
    def decode_string(input)
      asn1 = OpenSSL::ASN1.decode(input)

      decode_asn1(asn1)
    end

    # Decodes a Rex::Proto::Kerberos::Model::TicketEncPart
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
    #
    #    EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
    #            flags               [0] TicketFlags,
    #            key                 [1] EncryptionKey,
    #            crealm              [2] Realm,
    #            cname               [3] PrincipalName,
    #            transited           [4] TransitedEncoding,
    #            authtime            [5] KerberosTime,
    #            starttime           [6] KerberosTime OPTIONAL,
    #            endtime             [7] KerberosTime,
    #            renew-till          [8] KerberosTime OPTIONAL,
    #            caddr               [9] HostAddresses OPTIONAL,
    #            authorization-data  [10] AuthorizationData OPTIONAL
    #    }
    def decode_asn1(input)
      input.value[0].value.each do |val|
        case val.tag
        when 0  # flags               [0] TicketFlags
          self.flags = decode_flags(val)
        when 1  # key                 [1] EncryptionKey
          self.key = decode_key(val)
        when 2  # crealm              [2] Realm
          self.crealm = decode_crealm(val)
        when 3  # cname               [3] PrincipalName
          self.cname = decode_cname(val)
        when 4  # transited           [4] TransitedEncoding
          self.transited = decode_transited(val)
        when 5  # authtime            [5] KerberosTime
          self.authtime = decode_authtime(val)
        when 6  # starttime           [6] KerberosTime OPTIONAL
          self.starttime = decode_starttime(val)
        when 7  # endtime             [7] KerberosTime
          self.endtime = decode_endtime(val)
        when 8  # renew-till          [8] KerberosTime OPTIONAL
          self.renew_till = decode_renew_till(val)
        when 9  # caddr               [9] HostAddresses OPTIONAL
          self.caddr = decode_caddr(val)
        when 10 # authorization-data  [10] AuthorizationData OPTIONAL
          self.authorization_data = decode_authorization_data(val)
        else
          raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode TicketEncPart SEQUENCE'
        end
      end
    end

    # Decodes the flags from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [TicketFlags]
    def decode_flags(input)
      Rex::Proto::Kerberos::Helper.decode_ticket_flags(input)
    end

    # Encodes the flags
    #
    # @return [OpenSSL::ASN1::BitString]
    def encode_flags
      Rex::Proto::Kerberos::Helper.encode_ticket_flags(flags)
    end

    # Decodes the key from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [EncryptionKey]
    def decode_key(input)
      Rex::Proto::Kerberos::Helper.decode_encryption_key(input)
    end

    # Encodes the key
    #
    # @return [OpenSSL::ASN1::Sequence]
    def encode_key
      Rex::Proto::Kerberos::Helper.encode_encryption_key(key)
    end

    # Decodes the crealm from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [String]
    def decode_crealm(input)
      Rex::Proto::Kerberos::Helper.decode_realm(input)
    end

    # Encodes the crealm
    #
    # @return [OpenSSL::ASN1::GeneralString]
    def encode_crealm
      Rex::Proto::Kerberos::Helper.encode_realm(crealm)
    end

    # Decodes the cname from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [PrincipalName]
    def decode_cname(input)
      Rex::Proto::Kerberos::Helper.decode_principal_name(input)
    end

    # Encodes the cname
    #
    # @return [String]
    def encode_cname
      Rex::Proto::Kerberos::Helper.encode_principal_name(cname)
    end

    # Decodes the transited from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [TransitedEncoding]
    def decode_transited(input)
      Rex::Proto::Kerberos::Helper.decode_transited_encoding(input)
    end

    # Encodes the transited
    #
    # @return [String]
    def encode_transited
      Rex::Proto::Kerberos::Helper.encode_transited_encoding(transited)
    end

    # Decodes the authtime from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [Time]
    def decode_authtime(input)
      Rex::Proto::Kerberos::Helper.decode_kerberos_time(input)
    end

    # Encodes the authtime
    #
    # @return [OpenSSL::ASN1::GeneralizedTime]
    def encode_authtime
      Rex::Proto::Kerberos::Helper.encode_kerberos_time(authtime)
    end

    # Decodes the starttime from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [Time]
    def decode_starttime(input)
      Rex::Proto::Kerberos::Helper.decode_kerberos_time(input)
    end

    # Encodes the starttime
    #
    # @return [OpenSSL::ASN1::GeneralizedTime]
    def encode_starttime
      Rex::Proto::Kerberos::Helper.encode_kerberos_time(starttime)
    end

    # Decodes the endtime from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [Time]
    def decode_endtime(input)
      Rex::Proto::Kerberos::Helper.decode_kerberos_time(input)
    end

    # Encodes the endtime
    #
    # @return [OpenSSL::ASN1::GeneralizedTime]
    def encode_endtime
      Rex::Proto::Kerberos::Helper.encode_kerberos_time(endtime)
    end

    # Decodes the renew_till from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [Time]
    def decode_renew_till(input)
      Rex::Proto::Kerberos::Helper.decode_kerberos_time(input)
    end

    # Encodes the renew_till
    #
    # @return [OpenSSL::ASN1::GeneralizedTime]
    def encode_renew_till
      Rex::Proto::Kerberos::Helper.encode_kerberos_time(renew_till)
    end

    # Decodes the caddr from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [HostAddress]
    def decode_caddr(input)
      Rex::Proto::Kerberos::Helper.decode_host_address(input)
    end

    # Encodes the caddr
    #
    # @return [String]
    def encode_caddr
      Rex::Proto::Kerberos::Helper.encode_host_address(caddr)
    end

    # Decodes the authorization_data from an OpenSSL::ASN1::ASN1Data
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @return [AuthorizationData]
    def decode_authorization_data(input)
      Rex::Proto::Kerberos::Helper.decode_authorization_data(input)
    end

    # Encodes the authorization_data
    #
    # @return [String]
    def encode_authorization_data
      Rex::Proto::Kerberos::Helper.encode_authorization_data(authorization_data)
    end
  end
end
