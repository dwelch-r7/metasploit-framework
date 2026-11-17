# frozen_string_literal: true

require_relative '../wordpress/plugin_sources'

WordpressPluginSources.prepare(directory: File.expand_path('../elementor', __dir__), cache_name: 'elementor')
WordpressPluginSources.prepare(directory: __dir__, cache_name: 'king-addons')
