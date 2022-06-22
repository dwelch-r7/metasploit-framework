# -*- coding: binary -*-

module Rex::Proto::Kerberos::Model
  # This class provides a representation of a Kerberos ticket that helps
  # a client authenticate to a service.
  class TransitedEncoding < Element

    attr_accessor :tr_type  # [0] Int32 -- must be registered --,
    attr_accessor :contents # [1] OCTET STRING


    # Decodes the Rex::Proto::Kerberos::Model::TransitedEncoding from an input
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
        raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode TransitedEncoding, invalid input'
      end

      self
    end

    def encode
      elems = []
      elems << OpenSSL::ASN1::ASN1Data.new([encode_tr_type], 0, :CONTEXT_SPECIFIC)
      elems << OpenSSL::ASN1::ASN1Data.new([encode_contents], 1, :CONTEXT_SPECIFIC)

      seq = OpenSSL::ASN1::Sequence.new(elems)

      seq.to_der
    end

    private

    # Decodes a Rex::Proto::Kerberos::Model::TicketEncPart from an String
    #
    # @param input [String] the input to decode from
    def decode_string(input)
      asn1 = OpenSSL::ASN1.decode(input)

      decode_asn1(asn1)
    end

    # Decodes a Rex::Proto::Kerberos::Model::TransitedEncoding
    #
    # @param input [OpenSSL::ASN1::ASN1Data] the input to decode from
    # @raise [Rex::Proto::Kerberos::Model::Error::KerberosDecodingError] if decoding doesn't succeed
    #
    #    TransitedEncoding       ::= SEQUENCE {
    #            tr-type         [0] Int32 -- must be registered --,
    #            contents        [1] OCTET STRING
    #    }
    def decode_asn1(input)
      input.value.each do |val|
        case val.tag
        when 0  # tr-type         [0] Int32 -- must be registered --,
          self.tr_type = decode_tr_type(val)
        when 1  # contents        [1] OCTET STRING
          self.contents = decode_contents(val)
        else
          raise ::Rex::Proto::Kerberos::Model::Error::KerberosDecodingError, 'Failed to decode TransitedEncoding SEQUENCE'
        end
      end
    end

    def decode_tr_type(input)
      Rex::Proto::Kerberos::Helper.parse_int_32(input)
    end

    def encode_tr_type
      Rex::Proto::Kerberos::Helper.encode_int_32(tr_type)
    end

    def decode_contents(input)
      Rex::Proto::Kerberos::Helper.parse_octet_string(input)
    end

    def encode_contents
      Rex::Proto::Kerberos::Helper.encode_octet_string(contents)
    end
  end
end
