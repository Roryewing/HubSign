# frozen_string_literal: true

module Api
  # HubSign addition: create a one-off template from base64 PDFs with fields placed by the caller, so a host app can
  # send a freshly generated document without drawing fields in the editor. Field areas are fractions of the page
  # (0..1, origin top-left), page is 0-based, document is the 0-based index into `documents`.
  class TemplatesPdfController < ApiBaseController
    FIELD_TYPES = %w[signature initials text date datenow name checkbox].freeze

    def create
      template = build_template
      authorize!(:create, template)

      return render_error('roles is required') if template.submitters.blank?

      template.save!
      attachments = Array(params[:documents]).map { |d| attach(template, d) }
      return render_error('documents is required') if attachments.empty?

      fill(template, attachments)

      render json: Templates::SerializeForApi.call(template)
    rescue ArgumentError => e
      render_error(e.message)
    end

    private

    def build_template
      Template.new(account: current_account, author: current_user, source: :api,
                   name: params[:name].presence || 'Document', external_id: params[:external_id].presence,
                   folder: TemplateFolders.find_or_create_by_name(current_user, params[:folder_name]),
                   submitters: Array(params[:roles]).map do |name|
                     { 'name' => name.to_s, 'uuid' => SecureRandom.uuid }
                   end)
    end

    def fill(template, attachments)
      template.schema = attachments.map { |a| { attachment_uuid: a.uuid, name: a.filename.base } }
      template.fields = Array(params[:fields]).map { |f| build_field(template, attachments, f) }
      template.save!
    end

    def render_error(message)
      render json: { error: message }, status: :unprocessable_content
    end

    def attach(template, doc)
      data = Base64.strict_decode64(doc[:file_base64].to_s.gsub(/\s/, ''))
      tempfile = Tempfile.new(['hubsign', '.pdf'], binmode: true)
      tempfile.write(data)
      tempfile.rewind
      file = ActionDispatch::Http::UploadedFile.new(tempfile:, filename: "#{doc[:name].presence || 'document'}.pdf",
                                                    type: Templates::CreateAttachments::PDF_CONTENT_TYPE)
      Templates::CreateAttachments.call(template, { files: [file] }).first.first
    end

    def build_field(template, attachments, field)
      submitter = template.submitters.find { |s| s['name'] == field[:role].to_s }
      raise ArgumentError, "unknown role: #{field[:role]}" unless submitter

      type = field[:type].to_s
      raise ArgumentError, "unknown field type: #{type}" unless FIELD_TYPES.include?(type)

      {
        'uuid' => SecureRandom.uuid, 'submitter_uuid' => submitter['uuid'], 'name' => field[:name].to_s, 'type' => type,
        'required' => field[:required] != false, 'preferences' => field[:preferences].try(:to_unsafe_h) || {},
        'areas' => Array(field[:areas]).map do |a|
          attachment = attachments[a[:document].to_i] or raise ArgumentError, "unknown document: #{a[:document]}"
          { 'attachment_uuid' => attachment.uuid, 'page' => a[:page].to_i,
            'x' => a[:x].to_f, 'y' => a[:y].to_f, 'w' => a[:w].to_f, 'h' => a[:h].to_f }
        end
      }
    end
  end
end
