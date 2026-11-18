# frozen_string_literal: true

require 'base64'
require 'digest'

# Record real owner calls and HTTP responses without replacing target behavior.
module AirflowDagObservation
  OWNER = 'exploit/linux/http/apache_airflow_dag_rce'
  METHODS = %i[check check_api check_task check_unpaused create_dag await_execution exploit].freeze

  def self.install(framework)
    source = File.expand_path('modules/exploits/linux/http/apache_airflow_dag_rce.rb')
    events = []
    owner = framework.modules.create(OWNER)
    observer = Module.new do
      define_method(:send_request_cgi) do |*arguments, **keywords|
        response = super(*arguments, **keywords)
        events << {
          event: 'http', method: arguments.first.fetch('method', 'GET'), uri: arguments.first['uri'], request: arguments.first,
          code: response&.code, body_sha256: response && Digest::SHA256.hexdigest(response.body.b),
          body_base64: response && arguments.first['method'] == 'POST' && Base64.strict_encode64(response.body.b), object: object_id
        }
        response
      end
    end
    owner.class.prepend(observer)
    trace = TracePoint.new(:call, :return) do |event|
      next unless METHODS.include?(event.method_id)
      next unless event.path == source || File.expand_path(event.path) == source

      row = { event: event.event, method: event.method_id, object: event.self.object_id, auto_check: event.self.datastore['AutoCheck'] }
      if event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        result = event.return_value
        row[:result] = { code: result.code, reason: result.reason, message: result.message }
      end
      events << row
    end
    framework.instance_variable_set(:@airflow_events, events)
    framework.instance_variable_set(:@airflow_trace, trace)
    trace.enable
    { installed: true, owner_sha256: Digest::SHA256.file(source).hexdigest, config: Msf::Config.config_directory }
  end
end
