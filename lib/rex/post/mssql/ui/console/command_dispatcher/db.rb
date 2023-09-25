# -*- coding: binary -*-

require 'pathname'
require 'readline'

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # Core MSSQL client commands
        #
        ###
        class Console::CommandDispatcher::DB

          include Rex::Post::MSSQL::Ui::Console::CommandDispatcher

          # https://www.postgresql.org/docs/current/catalog-pg-database.html
          # @type [Hash<String, String>]
          DEFAULT_COLUMN_MAPPINGS = {
            'oid' => 'Row ID',
            'datname' => 'Name',
            'datdba' => 'Owner ID',
            'encoding' => 'Encoding',
            'datlocprovider' => 'Locale Provider',
            'datistemplate' => 'Template?',
            'datallowconn' => 'Allow Connections?',
            'datconnlimit' => 'Connection Limit',
            'datfrozenxid' => 'Frozen XID',
            'datminmxid' => 'Multixact ID',
            'dattablespace' => 'Tablespace ID',
            'datcollate' => 'LC_COLLATE',
            'datctype' => 'LC_CTYPE',
            'daticulocale' => 'ICU Locale',
            'daticurules' => 'ICU Rules',
            'datcollversion' => 'Collation Version',
            'datacl' => 'Access Privileges'
          }

          #
          # Initializes an instance of the core command set using the supplied console
          # for interactivity.
          #
          # @param [Rex::Post::MSSQL::Ui::Console] console
          def initialize(console)
            super

            @db_search_results = []
          end

          @@db_opts = Rex::Parser::Arguments.new(
            ["-h", "--help"] => [false, 'Help menu' ],
            ["-l", "--list"] => [ false,  "List all databases"],
            ["-t", "--tables"] => [ false,  "List all tables in the current database"],
            ["-i", "--interact"] => [ true,  "Interact with the supplied database", "database"],
            )

          #
          # List of supported commands.
          #
          def commands
            cmds = {
              'db'      => 'View the available databases and interact with one',
              'tables'  => 'View the available tables in the currently selected DB',
              'sql'     => 'Run a raw SQL query',
              'query'   => 'Run a raw SQL query',
              'shell'   => 'Enter a raw shell where SQL queries can be executed',
            }

            reqs = {}

            filter_commands(cmds, reqs)
          end

          def name
            'DB'
          end

          def help_args?(args)
            return false unless args.instance_of?(::Array)

            args.include?('-h') || args.include?('--help')
          end

          def cmd_shell_help
            print_line 'Usage: shell'
            print_line
            print_line 'Go into a raw SQL shell where SQL queries can be executed'
            print_line
          end

          def cmd_shell(*args)
            if help_args?(args)
              cmd_shell_help
              return
            end

            multiline_query = false
            raw_query = ''
            while (line = ::Readline.readline("SQL #{'*' if multiline_query} > ", true))
              raw_query << line << ' '

              query_finished = !line.chomp.end_with?('\\')
              break if query_finished

              multiline_query = true
            end

            # Format multi-line query
            formatted_query = raw_query.split.map { |word| word unless word == '\\' }.join(' ')

            self.cmd_query(formatted_query)
          end

          def cmd_query_help
            print_line 'Usage: query'
            print_line
            print_line 'You can also use `sql`.'
            print_line 'Run a raw SQL query on the target.'
            print_line
          end

          #
          # @param [::Msf::Db::MSSQL::Connection::Result] result The result of an SQL query to format.
          # @param [Hash<String, String>] mapped_columns
          def format_result(result, mapped_columns = {})
            columns = ['#']
            columns.append(result.fields.map.each { |field| field[:name] })
            flat_columns = columns.flatten
            columns_to_map = DEFAULT_COLUMN_MAPPINGS.merge(mapped_columns)
            flat_mapped_columns = flat_columns.map { |col| columns_to_map[col] || col }

            ::Rex::Text::Table.new(
              'Header' => 'Query',
              'Indent' => 4,
              'Columns' => flat_mapped_columns,
              'Rows' => result.rows.map.each.with_index do |row, i|
                [i, row].flatten
              end
            )
          end

          def cmd_query(*args)
            help_out = args.include?('-h') || args.include?('--help')
            self.cmd_query_help && return if help_out

            result = self.client.query(args.join(' ').to_s)
            table = self.format_result(result)

            print_line table.to_s
          end

          alias cmd_sql cmd_query
          alias cmd_sql_help cmd_query_help

          def cmd_db_help
            print_line 'Usage: db'
            print_line
            print_line 'View the databases available on the remote target.'
            print_line
          end

          #
          # Open the Pry debugger on the current session
          #
          def cmd_db(*args)
            if args.include?('-h') || args.include?('--help')
              cmd_db_help
              return
            end

            method = :list
            share_name = nil

            # Parse options
            @@db_opts.parse(args) do |opt, idx, val|
              case opt
              when '-l', '--list'
                method = :list
              when '-t', '--tables'
                method = :tables
              when '-i', '--interact'
                share_name = val
                method = :interact
              end
            end

            # Perform action
            case method
            when :tables
              # TODO: Print all tables in the current DB
            when :list
              result = self.client.query('SELECT datname, datdba, encoding, datcollate, datctype, datistemplate FROM pg_database;')
              print_line self.format_result(result).to_s
            when :interact
              # TODO Verify if share names can contain only digits, and if this would cause issues with this shortcut logic
              share_name = (@share_search_results[share_name.to_i] || {})[:name] if share_name.match?(/\A\d+\z/)
              if share_name.nil?
                print_error("Invalid share name")
                return
              end

              path = "\\\\#{address}\\#{share_name}"
              begin
                # TODO:
                # shell.active.disconnect! if shell.active
                shell.active_share = client.tree_connect(path)
                shell.cwd = ''
                print_good "Successfully connected to #{share_name}"
              rescue ::StandardError => e
                log_error("Error running action #{method}: #{e.class} #{e}")
              end
            end
          end

          def cmd_db_tabs(_str, words)
            return [] if words.length > 1

            @@db_opts.option_keys
          end

          def cmd_db_help
            print_line 'Usage: db'
            print_line
            print_line 'View the databases available on the remote target.'
            print_line
          end

          protected

          def print_no_db_selected
            print_error("No active database selected")
            nil
          end
        end
      end
    end
  end
end
