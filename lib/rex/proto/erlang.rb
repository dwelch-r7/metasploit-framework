# frozen_string_literal: true

require 'rex/exceptions'

module Rex
  module Proto
    module Erlang
      # A malformed or unsupported External Term Format value.
      class DecodeError < Rex::RuntimeError; end

      # Bounded decoding of the ETF forms used in distribution RPC replies.
      # Ports, references, functions, maps, binaries and floats are deliberately
      # unsupported; callers must handle DecodeError rather than guessing.
      # https://www.erlang.org/docs/25/apps/erts/erl_ext_dist.html
      class ExternalTerm
        MAX_BYTES = 1_048_576
        MAX_TERMS = 65_536
        MAX_DEPTH = 32
        VERSION_MAGIC = 131

        # @!attribute [rw] value
        #   @return [String] The atom text, normalized to UTF-8.
        Atom = Struct.new(:value, keyword_init: true)
        # @!attribute [rw] elements
        #   @return [Array] The tuple elements, distinguished from a list.
        Tuple = Struct.new(:elements, keyword_init: true)
        # @!attribute [rw] node
        #   @return [String] The node atom text.
        # @!attribute [rw] id
        #   @return [Integer] The process identifier.
        # @!attribute [rw] serial
        #   @return [Integer] The process serial.
        # @!attribute [rw] creation
        #   @return [Integer] The node incarnation identifier.
        Pid = Struct.new(:node, :id, :serial, :creation, keyword_init: true)

        # Decode one version-prefixed term without consuming subsequent terms.
        #
        # @param data [String] The ETF bytes, possibly followed by another term.
        # @return [Hash] The decoded :term and unconsumed binary :remaining.
        # @raise [ArgumentError] If data is not a String.
        # @raise [DecodeError] If a term is malformed, unsupported or over budget.
        def self.decode(data)
          new(data).decode
        end

        # @param data [String] The bytes to decode.
        # @return [void]
        # @raise [ArgumentError] If data is not a String.
        # @raise [DecodeError] If data exceeds the size budget.
        def initialize(data)
          raise ArgumentError, 'ETF data must be a String' unless data.is_a?(String)
          raise DecodeError, 'ETF data exceeds the size limit' if data.bytesize > MAX_BYTES

          @data = data.b
          @offset = 0
          @terms = 0
        end

        # Decode the next version-prefixed term from this decoder's cursor.
        #
        # @return [Hash] The decoded :term and unconsumed binary :remaining.
        # @raise [DecodeError] If a term is malformed, unsupported or over budget.
        def decode
          raise DecodeError, 'Invalid ETF version marker' unless read(1).unpack1('C') == VERSION_MAGIC

          { term: read_term(0), remaining: @data.byteslice(@offset..) }
        end

        private

        def read(length)
          raise DecodeError, 'Truncated ETF value' if length > @data.bytesize - @offset

          value = @data.byteslice(@offset, length)
          @offset += length
          value
        end

        def read_children(count, depth)
          raise DecodeError, 'ETF child count exceeds the remaining data' if count > @data.bytesize - @offset

          Array.new(count) { read_term(depth) }
        end

        def atom(length, utf8:)
          value = read(length).force_encoding(utf8 ? ::Encoding::UTF_8 : ::Encoding::ISO_8859_1)
          raise DecodeError, 'Invalid UTF-8 ETF atom' unless value.valid_encoding?

          value = value.encode(::Encoding::UTF_8)
          raise DecodeError, 'ETF atom exceeds 255 characters' if value.length > 255

          Atom.new(value: value)
        end

        def read_term(depth)
          raise DecodeError, 'ETF nesting exceeds the depth limit' if depth > MAX_DEPTH

          @terms += 1
          raise DecodeError, 'ETF value exceeds the term limit' if @terms > MAX_TERMS

          tag = read(1).unpack1('C')
          case tag
          when 97 # SMALL_INTEGER_EXT
            read(1).unpack1('C')
          when 98 # INTEGER_EXT
            read(4).unpack1('l>')
          when 100, 118 # ATOM_EXT, ATOM_UTF8_EXT
            atom(read(2).unpack1('n'), utf8: tag == 118)
          when 115, 119 # SMALL_ATOM_EXT, SMALL_ATOM_UTF8_EXT
            atom(read(1).unpack1('C'), utf8: tag == 119)
          when 103, 88 # PID_EXT, NEW_PID_EXT
            node = read_term(depth + 1)
            raise DecodeError, 'ETF PID node must be an atom' unless node.is_a?(Atom)

            Pid.new(node: node.value, id: read(4).unpack1('N'), serial: read(4).unpack1('N'), creation: tag == 103 ? read(1).unpack1('C') : read(4).unpack1('N'))
          when 104 # SMALL_TUPLE_EXT
            Tuple.new(elements: read_children(read(1).unpack1('C'), depth + 1))
          when 105 # LARGE_TUPLE_EXT
            Tuple.new(elements: read_children(read(4).unpack1('N'), depth + 1))
          when 106 # NIL_EXT
            []
          when 107 # STRING_EXT is an optimized list of bytes.
            read(read(2).unpack1('n'))
          when 108 # Only proper LIST_EXT values are supported.
            values = read_children(read(4).unpack1('N'), depth + 1)
            tail = read_term(depth + 1)
            tail = tail.bytes if tail.is_a?(String)
            raise DecodeError, 'Improper ETF lists are unsupported' unless tail.is_a?(Array)

            values.concat(tail)
          else
            raise DecodeError, "Unsupported ETF tag #{tag}"
          end
        end
      end
    end
  end
end
