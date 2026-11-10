# frozen_string_literal: true

require_relative 'native_base'

# Confirms stock JSP routing at the genuine affected/fixed release boundary.
class ActiveMqDisclosureNative < LegacyActiveMqNative
  def run
    PROVENANCE.fetch('profiles').fetch('disclosure').each do |service, version|
      identity(service, version)
      pages = %w[index.jsp queues.jsp topics.jsp].map do |page|
        source = command(service, 'cat', "/opt/activemq/webapps/admin/#{page}")
        raise 'Native stock page has no JSP code' unless source.include?('<%')

        rendered = request(service, 'GET', "/admin/#{page}")
        disclosed = request(service, 'GET', "//admin/#{page}")
        raise 'Native normal JSP did not render' unless rendered.fetch(:code) == 200 && !Base64.strict_decode64(rendered.fetch(:body_base64)).include?('<%')

        if service == 'affected'
          raise 'Native raw JSP mismatch' unless disclosed.fetch(:code) == 200 && disclosed.fetch(:body_sha256) == Digest::SHA256.hexdigest(source)
        else
          raise 'Native fixed raw path policy mismatch' unless disclosed.fetch(:code) == 404
        end
        { page: page, source_sha256: Digest::SHA256.hexdigest(source), rendered: rendered, disclosed: disclosed }
      end
      missing = request(service, 'GET', '//admin/module-target-missing.jsp')
      raise 'Native missing path mismatch' unless missing.fetch(:code) == 404

      root = request(service, 'GET', '/')
      raise 'Native static index policy mismatch' unless root.fetch(:code) == 200 && !Base64.strict_decode64(root.fetch(:body_base64)).include?('<%')

      @records[:profiles][service][:pages] = pages
      @records[:profiles][service][:root] = root
    end
    version = command('unrelated', 'httpd', '-v')
    raise 'Native unrelated product mismatch' unless version.include?('Apache/2.4.62')

    output = command('affected', 'curl', '--silent', '--show-error', '--globoff', '--path-as-is', '--max-time', '5', '--write-out', "\nMODULE_TARGET_STATUS=%{http_code}", 'http://unrelated/') # rubocop:disable Style/FormatStringToken
    body, marker, code = output.rpartition("\nMODULE_TARGET_STATUS=")
    raise 'Native unrelated HTML policy mismatch' unless !marker.empty? && code == '200' && !body.include?('<%')

    @records[:profiles]['unrelated'] = { version: version, root_code: code, root_body_base64: Base64.strict_encode64(body) }
    @records[:http] << { service: 'unrelated', requested_from: 'affected', method: 'GET', path: '/', code: Integer(code), body_base64: Base64.strict_encode64(body), body_sha256: Digest::SHA256.hexdigest(body) }
    @records
  ensure
    save_partial('native-disclosure-partial.json')
  end
end

puts JSON.pretty_generate(ActiveMqDisclosureNative.new.run) if $PROGRAM_NAME == __FILE__
