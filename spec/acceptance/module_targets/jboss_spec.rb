require 'acceptance_spec_helper'
require 'nokogiri'

RSpec.describe 'Native JBoss management and administration targets' do
  include_context 'native JBoss target'

  it 'collects the real client, virtual host and request query on repeated status reads' do
    2.times do
      with_held_request do
        native = native_http('open', '/status')
        expect(native.body).to include('module-target-jboss-secret')
        row = Nokogiri::HTML(native.body).css('tr').find { |entry| entry.text.include?('module-target-jboss-secret') }
        expect(row).not_to be_nil
        fields = row.css('td').map(&:text).last(3)
        expect(fields.size).to eq(3)
        output = run_target_module('auxiliary/scanner/http/jboss_status', 'open', { 'TARGETURI' => '/status' })
        expect(output).to include('JBoss application server found', 'module-target-jboss-secret', 'jboss.module-target.test')
        expect(output).to include(*fields)
      end
    end
  end

  %w[legacy secured].each do |service|
    it "reports actual status authentication on #{service}" do
      output = run_target_module('auxiliary/scanner/http/jboss_status', service, {}, allow_errors: true)
      expect(output).to include('Authentication is required')
      expect(output).not_to include('JBoss application server found')
    end
  end

  it 'does not identify unrelated HTTP as the JBoss status servlet' do
    output = run_target_module('auxiliary/scanner/http/jboss_status', 'unrelated', {}, allow_errors: true)
    expect(output).to include('Unknown error')
    expect(output).not_to include('JBoss application server found')
  end

  %w[open legacy secured].each do |service|
    it "scans actual management policies and listening services on #{service}" do
      output = run_target_module('auxiliary/scanner/http/jboss_vulnscan', service, { 'VERB' => 'HEAD' }, allow_errors: true)
      expected = service == 'open' ? '/jmx-console/HtmlAdaptor does not require authentication (200)' : '/jmx-console/HtmlAdaptor requires authentication (401)'
      expect(output).to include(expected)
      paths = @native.fetch(service).fetch('scanned').except('/admin-console/login.seam').merge('/status' => @native.fetch(service).fetch('status'))
      paths.each do |path, response|
        message = case response.fetch('code')
                  when 200 then 'does not require authentication (200)'
                  when 401 then 'requires authentication (401)'
                  when 500 then 'responded (500)'
                  else raise "Unexpected native fixture status for #{path}"
                  end
        expect(output).to include("#{path} #{message}")
      end
      expect(output).to include('tcp/1098: open', 'tcp/1099: open', 'tcp/4444: open')
      expect(output).to include('Authenticated using admin:admin at /jmx-console/HtmlAdaptor') if service == 'secured'
      expect(output).not_to include('Got authentication bypass') if service == 'secured'
      # AS 4.2.3 dispatches HEAD before its vendor RequestDispatcher returns 500.
      # Native BSH and repository controls prove the bypass; this scanner only
      # recognizes 200 and its current limitation remains visible in the trace.
      expect(output).to include('Could not get authentication bypass') if service == 'legacy'
    end
  end

  it 'reports actual missing management paths and closed services on unrelated HTTP' do
    output = run_target_module('auxiliary/scanner/http/jboss_vulnscan', 'unrelated', {}, allow_errors: true)
    expect(output).to include('/jmx-console/HtmlAdaptor not found (404)', 'tcp/1098: closed', 'tcp/1099: closed', 'tcp/4444: closed')
    expect(output).not_to include('does not require authentication', 'Authenticated using', 'Got authentication bypass')
  end

  %w[bshdeployer deploymentfilerepository].each do |name|
    [ ['open', 'POST', {}], ['open', 'GET', {}], ['legacy', 'HEAD', {}], ['secured', 'POST', { 'HttpUsername' => 'admin', 'HttpPassword' => 'admin' }] ].each do |service, verb, credentials|
      it "deploys and undeploys an actual WAR twice through #{name} #{service}/#{verb}" do
        original = deployment_files(service)
        registry = deployment_registry(service)
        begin
          2.times do
            output = admin(name, service, verb, credentials.merge('WARFILE' => @warfile), allow_errors: verb == 'HEAD')
            expect(output).to match(/Deployment successful|Payload deployed/)
            wait_for_expect(60, 0.2) do
              expect(native_http(service, '/module-target-admin/index.jsp').body).to include('module-target-jboss-native', 'account=root', 'java=1.8.0_412')
            end
            # Final WAR exists, but every temporary stager must be gone.
            remaining = deployment_files(service) - original
            expected = name == 'bshdeployer' ? 'module-target-admin.war f' : 'management/module-target-admin.war f'
            expect(remaining).to eq([expected])
            expect(target_exec(service, 'sha256sum', "/opt/jboss/server/default/deploy/#{expected.delete_suffix(' f')}").split.first).to eq(@war_sha256)
            removed = admin(name, service, verb, credentials.merge('ACTION' => 'Undeploy'), allow_errors: verb == 'HEAD')
            if verb == 'HEAD'
              # The native controls demonstrate that the vendor dispatches the
              # operation before returning 500. Require independent restoration
              # below; neither this response nor the module banner proves it.
              message = name == 'bshdeployer' ? 'Unable to remove WAR' : 'Unable to remove WAR [500 Internal Server Error]'
              expect(removed).to include(message)
            else
              expect(removed).to include('Successfully removed')
            end
            expect(deployment_files(service)).to eq(original)
            wait_for_expect(30, 0.2) { expect(deployment_registry(service)).to eq(registry) }
            expect(native_http(service, '/module-target-admin/index.jsp').code).to eq('404')
          end
        ensure
          cleanup_new_wars(service, original, registry)
        end
      end
    end

    [ {}, { 'HttpUsername' => 'admin', 'HttpPassword' => 'wrong-password' } ].each do |credentials|
      it "refuses #{credentials.empty? ? 'anonymous' : 'wrong-password'} #{name} deployment without target changes" do
        original = deployment_files('secured')
        output = admin(name, 'secured', 'POST', credentials.merge('WARFILE' => @warfile), allow_errors: true)
        expect(output).to match(/authentication|Failed to deploy|Deployment failed/i)
        expect(deployment_files('secured')).to eq(original)
        expect(native_http('secured', '/module-target-admin/index.jsp').code).to eq('404')
      end
    end

    it "refuses unrelated HTTP for #{name} without claiming deployment" do
      output = admin(name, 'unrelated', 'POST', { 'WARFILE' => @warfile }, allow_errors: true)
      expect(output).not_to match(/Deployment successful|Payload deployed|Successfully removed/)
      expect(output).to match(/Failed to deploy|Deployment failed|Unable to deploy/)
    end

    it "reports the actual missing WAR input for #{name}" do
      original = deployment_files('open')
      target_exec('framework', 'test', '!', '-e', '/module-target-missing.war')
      console_command('back')
      selected = console_command("use auxiliary/admin/http/jboss_#{name}")
      expect(selected).not_to match(/Failed to load|Unknown command/)
      endpoint = target_runtime.fetch('module_endpoints').fetch('open')
      output = console_command("run RHOSTS=#{endpoint.fetch('host')} RPORT=#{endpoint.fetch('port')} VERB=POST WARFILE=/module-target-missing.war")
      expect(output).to include('Msf::OptionValidateError One or more options failed to validate: WARFILE.')
      expect(output).not_to match(/Running module against|Deployment successful|Payload deployed|undefined method/)
      expect(deployment_files('open')).to eq(original)
    end
  end

  def admin(name, service, verb, options, allow_errors: false)
    run_target_module("auxiliary/admin/http/jboss_#{name}", service, { 'APPBASE' => 'module-target-admin', 'TARGETURI' => '/jmx-console', 'VERB' => verb }.merge(options), allow_errors: allow_errors, command_timeout: 65)
  end
end
