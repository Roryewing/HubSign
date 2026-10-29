# frozen_string_literal: true

module Api
  # HubSign addition: create a one-off template from base64 PDFs with fields placed by the caller, so a host app can
  # send a freshly generated document without drawing fields in the editor. Field areas are fractions of the page
  # (0..1, origin top-left), page is 0-based, document is the 0-based index into `documents`. A field may instead give
  # `anchor: { text:, x_offset:, y_offset:, width:, height:, optional: }`: it then gets one area (points, from the
  # top-left of the anchor's first character) at every place that text is printed, even invisibly.
  class TemplatesPdfController < ApiBaseController
    FIELD_TYPES = %w[signature initials text date datenow name checkbox].freeze
    # points, used when an anchored field gives no width/height
    DEFAULT_SIZE = {
      'signature' => [140, 36], 'initials' => [48, 30], 'date' => [90, 14], 'datenow' => [90, 14],
      'name' => [150, 14], 'text' => [160, 14], 'checkbox' => [12, 12]
    }.freeze

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

    def areas_for(attachments, field)
      return anchor_areas(attachments, field) if field[:anchor].present?

      Array(field[:areas]).map do |a|
        attachment = attachments[a[:document].to_i] or raise ArgumentError, "unknown document: #{a[:document]}"
        { 'attachment_uuid' => attachment.uuid, 'page' => a[:page].to_i,
          'x' => a[:x].to_f, 'y' => a[:y].to_f, 'w' => a[:w].to_f, 'h' => a[:h].to_f }
      end
    end

    def anchor_areas(attachments, field)
      anchor = field[:anchor]
      areas = attachments.each_with_index.flat_map do |attachment, index|
        next [] if anchor[:document].present? && anchor[:document].to_i != index

        anchor_hits(attachment, anchor, field[:type].to_s)
      end

      if areas.empty? && anchor[:optional] != true
        raise ArgumentError,
              "anchor text #{anchor[:text].inspect} was not found"
      end

      areas
    end

    def anchor_hits(attachment, anchor, type)
      width, height = DEFAULT_SIZE[type]
      width = anchor[:width].presence&.to_f || width
      height = anchor[:height].presence&.to_f || height
      doc = Pdfium::Document.open_bytes(attachment.download)

      doc.page_count.times.flat_map do |index|
        page = doc.get_page(index)

        begin
          page.find_text(anchor[:text].to_s).map do |hit|
            x = (hit[:x] + anchor[:x_offset].to_f).clamp(0, page.width - width)
            y = (hit[:y] + anchor[:y_offset].to_f).clamp(0, page.height - height)
            { 'attachment_uuid' => attachment.uuid, 'page' => index, 'x' => x / page.width, 'y' => y / page.height,
              'w' => width / page.width, 'h' => height / page.height }
          end
        ensure
          page.close
        end
      end
    ensure
      doc&.close
    end

    def build_field(template, attachments, field)
      submitter = template.submitters.find { |s| s['name'] == field[:role].to_s }
      raise ArgumentError, "unknown role: #{field[:role]}" unless submitter

      type = field[:type].to_s
      raise ArgumentError, "unknown field type: #{type}" unless FIELD_TYPES.include?(type)

      {
        'uuid' => SecureRandom.uuid, 'submitter_uuid' => submitter['uuid'], 'name' => field[:name].to_s, 'type' => type,
        'required' => field[:required] != false, 'preferences' => field[:preferences].try(:to_unsafe_h) || {},
        'areas' => areas_for(attachments, field)
      }
    end
  end
end
