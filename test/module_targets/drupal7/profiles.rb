# frozen_string_literal: true

# Select one installation without changing the original acceptance cases.
module Drupal7Profiles
  GROUP = 'Native Drupal 7 Drupalgeddon 2 targets'
  INSTALLATIONS = {
    'root' => ['', '7.57', true, true],
    'prefix' => ['/drupal', '7.57', true, true],
    'fixed' => ['', '7.58', false, false],
    'assert_off' => ['', '7.57', true, true],
    'no_changelog' => ['', '7.57', true, true]
  }.freeze

  def self.session_example(label, service)
    "opens #{label} twice on #{service} and cleans each delivery"
  end

  def self.denied_example(service, path = 'root')
    "does not execute a command on #{service} #{path} without a positive check"
  end

  PROFILES = {
    'drupal7' => {
      mode: 'command', drupal: ['root'], unrelated: false,
      examples: [
        'proves code execution in the actual root Drupal check',
        'does not identify a missing installation path as Drupal',
        'executes and reports the root Unix command twice with fresh proof',
        'initializes the Drupal 7 execution path with AutoCheck disabled',
        'supports the configured system function for Unix command execution',
        session_example('automatic Linux dropper', 'root'),
        denied_example('root', '/module-target-missing/')
      ]
    },
    'drupal7_prefix' => {
      mode: 'command', drupal: ['prefix'], unrelated: false,
      examples: [
        'proves code execution in the actual prefix Drupal check',
        'executes and reports the prefix Unix command twice with fresh proof',
        session_example('explicit Linux dropper', 'prefix')
      ]
    },
    'drupal7_assert_off' => {
      mode: 'command', drupal: ['assert_off'], unrelated: false,
      examples: ['proves code execution in the actual assert_off Drupal check', session_example('Linux dropper command fallback', 'assert_off')]
    },
    'drupal7_no_changelog' => {
      mode: 'command', drupal: ['no_changelog'], unrelated: false,
      examples: ['returns detected when the actual installation withholds its changelog', 'executes and reports the no_changelog Unix command twice with fresh proof']
    },
    'drupal7_fixed' => {
      mode: 'command', drupal: ['fixed'], unrelated: false,
      examples: ['identifies the actual fixing release as not vulnerable', 'keeps the fixing-release check safe under an explicit Drupal 7 target', denied_example('fixed')]
    },
    'drupal7_unrelated' => {
      mode: 'command', drupal: [], unrelated: true,
      examples: ['does not identify unrelated Apache as Drupal', denied_example('unrelated')]
    },
    'drupal7_php' => {
      mode: 'php', drupal: ['root'], unrelated: false,
      examples: [session_example('automatic PHP memory', 'root'), session_example('automatic PHP dropper', 'root')]
    },
    'drupal7_php_staged' => {
      mode: 'php', drupal: ['root'], unrelated: false,
      examples: [session_example('staged PHP Meterpreter', 'root')]
    },
    'drupal7_php_prefix' => {
      mode: 'php', drupal: ['prefix'], unrelated: false,
      examples: [session_example('explicit PHP memory', 'prefix'), session_example('explicit PHP dropper', 'prefix')]
    },
    'drupal7_php_assert_off' => {
      mode: 'php', drupal: ['assert_off'], unrelated: false,
      examples: [session_example('PHP memory command fallback', 'assert_off'), session_example('PHP dropper command fallback', 'assert_off')]
    }
  }.freeze

  def self.fetch(name)
    PROFILES.fetch(name) { raise ArgumentError, "Unknown Drupal 7 target profile: #{name}" }
  end

  def self.callback_services(profile)
    profile.fetch(:drupal).select { |service| INSTALLATIONS.fetch(service)[2] }
  end
end
