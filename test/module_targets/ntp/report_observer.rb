# frozen_string_literal: true

# Acceptance-only observation: preserve production reporting, retaining the
# gathered data even when this isolated console has no database.
module ModuleTargetNtpReports
  def report_service(options)
    record_ntp_report('service', options)
    super
  end

  def report_vuln(options)
    record_ntp_report('vulnerability', options)
    super
  end

  private

  def record_ntp_report(kind, options)
    File.open(File.join(Msf::Config.config_directory, 'ntp-reports.jsonl'), 'a') do |file|
      file.puts(JSON.generate(kind: kind, options: options))
    end
  end
end
