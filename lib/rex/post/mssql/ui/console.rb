# -*- coding: binary -*-

module Rex
  module Post
    module MSSQL
      module Ui
        ###
        #
        # This class provides a shell driven interface to the MSSQL client API.
        #
        ###
        class Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/mssql/ui/console/command_dispatcher'
          require 'rex/post/mssql/ui/console/command_dispatcher/core'
          require 'rex/post/mssql/ui/console/command_dispatcher/db'

          #
          # Initialize the MSSQL console.
          #
          # @param [Msf::Sessions::MSSQL] session
          def initialize(session)
            # The mssql client context
            self.session = session
            self.socket = session.socket
            prompt = "%undMSSQL @ #{session.address}:#{session.port}%clr"
            history_manager = self.session.framework&.history_manager&.with_context(name: :mssql)
            super(prompt, '>', history_manager, self.session&.framework, :mssql)

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::Core)
            enstack_dispatcher(::Rex::Post::MSSQL::Ui::Console::CommandDispatcher::DB)

            # Set up logging to whatever logsink 'core' is using
            if ! $dispatcher['mssql']
              $dispatcher['mssql'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the mssql client.  It's
          # assumed that init_ui has been called prior.
          #
          def interact(&block)
            # Run queued commands
            commands.delete_if do |ent|
              run_single(ent)
              true
            end

            # Run the interactive loop
            run do |line|
              # Run the command
              run_single(line)

              # If a block was supplied, call it, otherwise return false
              if block
                block.call
              else
                false
              end
            end
          end

          #
          # Queues a command to be run when the interactive loop is entered.
          #
          def queue_cmd(cmd)
            self.commands << cmd
          end

          #
          # Runs the specified command wrapper in something to catch meterpreter
          # exceptions.
          #
          def run_command(dispatcher, method, arguments)
            begin
              super
            rescue ::Timeout::Error
              log_error('Operation timed out.')
            rescue ::Rex::InvalidDestination => e
              log_error(e.message)
            rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError
              self.session.kill
            rescue ::StandardError => e
              log_error("Error running command #{method}: #{e.class} #{e}")
              elog(e)
            end
          end

          #
          # Logs that an error occurred and persists the callstack.
          #
          def log_error(msg)
            print_error(msg)

            elog(msg, 'mssql')

            dlog("Call stack:\n#{$@.join("\n")}", 'mssql')
          end

          # @return [Msf::Sessions::MSSQL]
          attr_reader :session

          # @return [MSSQL::Client]
          attr_reader :client # :nodoc:

          # TODO Should this belong elsewhere - it's required for prompt details
          # @return [String]
          attr_accessor :cwd

          def format_prompt(val)
            ## TODO: Verify how active_module impacts the prompt name, and follow the same pattern
            #if active_share
            #  share_name = active_share.share[/[^\\].*$/, 0] # active_share.share[/[^\\]+$/, 0]
            #  cwd = self.cwd.blank? ? '' : "\\#{self.cwd}"
            #  return substitute_colors("%undMSSQL%clr (#{share_name}#{cwd}) > ", true)
            #end

            super
          end

          protected

          attr_writer :session # :nodoc:
          attr_writer :socket # :nodoc:
          attr_accessor :commands # :nodoc:

        end

      end
    end
  end
end
