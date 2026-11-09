require 'metasploit/framework/login_scanner/http'
require 'nokogiri'

module Metasploit
  module Framework
    module LoginScanner

      # Wordpress XML RPC login scanner
      class WordpressRPC < HTTP

        # Checks if the target is a WordPress XML-RPC endpoint
        #
        # @return [false] if the target looks like a WordPress XML-RPC endpoint
        # @return [String] a human-readable error message if it doesn't
        def check_setup
          res = send_request({
            'method' => 'GET',
            'uri' => uri
          })

          return 'Unable to connect to the WordPress XML-RPC endpoint' unless res
          return 'Unable to locate WordPress XML-RPC endpoint (Is WordPress installed and is XML-RPC enabled?)' unless [200, 405].include?(res.code) && res.body.to_s.include?('XML-RPC server accepts POST requests only')

          report_service(service_opts)

          false
        end

        def service_opts
          build_service_opts('wordpress')
        end

        # (see Base#attempt_login)
        def attempt_login(credential)
          result_opts = {
            credential: credential,
            **service_as_result(service_opts)
          }

          begin
            response = send_request(
              {
                'uri' => uri,
                'method' => method,
                'ctype' => 'text/xml; charset=UTF-8',
                'data' => generate_xml_request(credential.public, credential.private)
              }
            )

            if response.nil?
              result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
            else
              status = Metasploit::Model::Login::Status::INCORRECT
              if response.code == 200
                document = response.get_xml_document
                fault_code = document.at_xpath('/methodResponse/fault/value/struct/member[name="faultCode"]/value/int')&.text
                user_id = document.at_xpath('/methodResponse/params/param/value/array/data/value/struct/member[name="user_id"]/value/*[self::string or self::int or self::i4]')&.text.to_s.strip
                valid_user_id = user_id.match?(/\A\d+\z/) && user_id.to_i.positive?
                if document.errors.empty?
                  # wp.getUsers authenticates before checking permission to list
                  # users, so the native 401 fault also proves valid credentials.
                  if fault_code == '401' || (fault_code.nil? && valid_user_id)
                    status = Metasploit::Model::Login::Status::SUCCESSFUL
                  elsif fault_code == '-32601'
                    status = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
                  end
                end
              end
              result_opts.merge!(status: status, proof: response)
            end
          rescue ::EOFError, Rex::ConnectionError, ::Timeout::Error => e
            result_opts.merge!(status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: e)
          end

          Result.new(result_opts)
        end

        # This method generates the XML data for the RPC login request
        # @param user [String] the username to authenticate with
        # @param pass [String] the password to authenticate with
        # @return [String] the generated XML body for the request
        def generate_xml_request(user, pass)
          Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
            xml.methodCall do
              xml.methodName('wp.getUsers')
              xml.params do
                ['1', user, pass].each do |value|
                  xml.param { xml.value { xml.string(value) } }
                end
              end
            end
          end.to_xml
        end

        # (see Base#set_sane_defaults)
        def set_sane_defaults
          @method = "POST".freeze
          super
        end

        def service_opts
          build_service_opts('wordpress')
        end

      end
    end
  end
end

