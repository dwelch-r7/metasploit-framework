# frozen_string_literal: true

require_relative '../wordpress/plugin_sources'

WordpressPluginSources.prepare(directory: __dir__, cache_name: 'learnpress-fields')
