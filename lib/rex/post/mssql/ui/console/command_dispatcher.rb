# -*- coding: binary -*-

require 'rex/ui/text/dispatcher_shell'

module Rex
  module Post
    module MSSQL
      module Ui
        include Msf::Exploit::Remote::MSSQL
        ###
        #
        # Base class for all command dispatchers within the MSSQL console user interface.
        #
        ###
        module Console::CommandDispatcher
          include Rex::Ui::Text::DispatcherShell::CommandDispatcher

          #
          # The hash of file names to class names after a module has already been
          # loaded once on the client side.
          #
          # @@file_hash = {}
          #
          # #
          # # Checks the file name to hash association to see if the module being
          # # requested has already been loaded once.
          # #
          # def self.check_hash(name)
          #   @@file_hash[name]
          # end
          #
          # #
          # # Sets the file path to class name association for future reference.
          # #
          # def self.set_hash(name, klass)
          #   @@file_hash[name] = klass
          # end

          #
          # Initializes an instance of the core command set using the supplied session and client
          # for interactivity.
          #
          # @param [Rex::Post::MSSQL::Ui::Console] console
          def initialize(console)
            super
            @msf_loaded = nil
            @filtered_commands = []
          end

          #
          # Returns the MSSQL client context.
          #
          # @return [MSSQL::Client]
          def client
            console = shell
            console.client
          end

          #
          # Returns the MSSQL session context.
          #
          # @return [Msf::Sessions::MSSQL]
          def session
            console = shell
            console.session
          end

          def address
            self.client.conn.remote_address.ip_address
          end

          def port
            self.client.conn.remote_address.ip_port
          end

          #
          # Returns the commands that meet the requirements
          #
          def filter_commands(all, reqs)
            all.delete_if do |cmd, _desc|
              if reqs[cmd]&.any? { |req| !client.commands.include?(req) }
                @filtered_commands << cmd
                true
              end
            end
          end

          def unknown_command(cmd, line)
            if @filtered_commands.include?(cmd)
              print_error("The \"#{cmd}\" command is not supported by this session type (#{client.session_type})")
              return :handled
            end

            super
          end

          #
          # Return the subdir of the `documentation/` directory that should be used
          # to find usage documentation
          #
          def docs_dir
            ::File.join(super, 'meterpreter')
          end

          #
          # Returns true if the client has a framework object.
          #
          # Used for firing framework session events
          #
          def msf_loaded?
            return @msf_loaded unless @msf_loaded.nil?

            # if we get here we must not have initialized yet
            @msf_loaded = !!(self.client.framework)
          end

          #
          # Log that an error occurred.
          #
          def log_error(msg)
            print_error(msg)

            elog(msg, 'mssql')

            dlog("Call stack:\n#{$@.join("\n")}", 'mssql')
          end

        end

      end
    end
  end
end
