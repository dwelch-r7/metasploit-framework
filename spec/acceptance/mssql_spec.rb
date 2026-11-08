# frozen_string_literal: true

require 'acceptance_spec_helper'
require 'json'
require 'open3'

RSpec.describe 'MSSQL sessions and MSSQL modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    mssql: {
      target: {
        session_module: 'auxiliary/scanner/mssql/mssql_login',
        type: 'MSSQL',
        platforms: [:linux, :osx, :windows],
        session_info_pattern: /MSSQL #{Regexp.escape(ENV.fetch('MSSQL_USER', 'sa'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            username: ENV.fetch('MSSQL_USER', 'sa'),
            password: ENV.fetch('MSSQL_PASSWORD', 'yourStrong(!)Password'),
            rhost: ENV.fetch('MSSQL_RHOST', '127.0.0.1'),
            rport: ENV.fetch('MSSQL_RPORT', '1433'),
            database: 'master'
          }
        }
      },
      module_tests: [
        {
          name: 'post/test/mssql',
          platforms: [:linux, :osx, :windows],
          targets: [:session],
          skipped: false,
        },
        {
          name: 'auxiliary/scanner/mssql/mssql_hashdump',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Instance Name: "\w+"/,
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/mssql/mssql_version',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Version: \d+.\d+.\d+/,
                /Encryption: (?:on|off|unsupported|required|unknown)/
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mssql/mssql_enum',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                'Version:',
                /Microsoft SQL Server \d+.\d+/,
                'Databases on the server:',
                'System Logins on this Server:'
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/mssql/mssql_schemadump',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Instance Name: "\w+"/,
                'Microsoft SQL Server Schema',
                'Host:',
                'Port:',
                'Instance:',
                'Version:'
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mssql/mssql_sql',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                'Response',
                'Microsoft SQL Server',
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mssql/mssql_sql',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { SQL: 'EXEC sp_databases' },
          lines: {
            all: {
              required: [
                'Response',
                'master',
              ]
            },
          }
        }
      ]
    }
  }

  if ENV['MSSQL_MODULE_TARGET'] == 'true'
    tests[:mssql][:module_tests] << {
      name: 'auxiliary/admin/mssql/mssql_sql',
      platforms: %i[linux osx windows],
      targets: %i[session rhost],
      datastore: { SQL: 'SELECT id, evidence FROM module_target_test.dbo.module_target_evidence' },
      lines: { all: { required: ['module-target-sql-marker'] } }
    }

    before(:all) do
      runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
      command = runtime.fetch('compose') + ['exec', '-T', 'mssql', '/opt/mssql-tools18/bin/sqlcmd', '-U', 'sa', '-P', 'yourStrong(!)Password', '-C', '-b', '-i', '/opt/module-target-seed.sql']
      output, status = Open3.capture2e(*command)
      File.write(File.join(runtime.fetch('artifacts'), 'native-seed.log'), "$ #{command.inspect}\n#{output}")
      expect(status.success?).to be(true), output
      expect(output).to include('module-target-sql-marker')
      password_hash = output[/^MODULE_TARGET_HASH=(0x[0-9a-fA-F]+)\s*$/, 1]
      expect(password_hash).to match(/\A0x0200[0-9a-fA-F]+\z/)

      # Compare the module's hash with an independent native query, rather than
      # accepting a generic save message or a well-shaped but unrelated hash.
      hashes = tests[:mssql][:module_tests].find { |entry| entry[:name].end_with?('/mssql_hashdump') }
      hashes[:lines][:all][:required] << "Saving mssql12 = sa:0x#{password_hash.delete_prefix('0x').upcase}"
      schema = tests[:mssql][:module_tests].find { |entry| entry[:name].end_with?('/mssql_schemadump') }
      schema[:lines][:all][:required] += ['DBName: module_target_test', 'TableName: module_target_evidence', 'ColumnName: evidence']
    end
  end

  run_protocol_session_tests(tests, features: %w[mssql_session_type])
end
