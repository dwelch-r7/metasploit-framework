# frozen_string_literal: true

require 'rbconfig'

root = File.expand_path('../../..', __dir__)
exec(RbConfig.ruby, File.join(root, 'tools/dev/run_guarded_module_target_tests.rb'), *%w[capture_mysql capture_mysql_oracle_mariadb capture_mysql_mariadb_mysql capture_mysql_mariadb_mariadb capture_mssql])
