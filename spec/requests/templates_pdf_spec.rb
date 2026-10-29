# frozen_string_literal: true

describe 'Templates PDF API' do
  let(:account) { create(:account) }
  let(:author) { create(:user, account:) }
  let(:pdf) { Base64.strict_encode64(Rails.root.join('spec/fixtures/sample-document.pdf').binread) }

  it 'creates a template from a PDF with placed fields' do
    post '/api/templates/pdf',
         params: { name: 'FX', roles: %w[HJV Customer], documents: [{ name: 'FX', file_base64: pdf }],
                   fields: [{ name: 'hjv-sign', role: 'HJV', type: 'signature',
                              areas: [{ document: 0, page: 0, x: 0.1, y: 0.8, w: 0.3, h: 0.05 }] }] }.to_json,
         headers: { 'x-auth-token': author.access_token.token, 'content-type': 'application/json' }

    expect(response).to have_http_status(:ok)
    body = response.parsed_body
    expect(body['submitters'].pluck('name')).to eq(%w[HJV Customer])
    expect(body['fields'].first['areas'].first).to include('page' => 0, 'x' => 0.1)
    expect(body['documents'].size).to eq(1)
  end

  it 'rejects a field for an unknown role' do
    post '/api/templates/pdf',
         params: { roles: %w[A], documents: [{ file_base64: pdf }],
                   fields: [{ name: 'x', role: 'B', type: 'text' }] }.to_json,
         headers: { 'x-auth-token': author.access_token.token, 'content-type': 'application/json' }

    expect(response).to have_http_status(:unprocessable_content)
  end

  it 'places fields on invisible anchor text, one per occurrence' do
    doc = HexaPDF::Document.new
    2.times do
      canvas = doc.pages.add([0, 0, 612, 792]).canvas
      canvas.font('Helvetica', size: 2).fill_color(1, 1, 1).text('~cus-sign~', at: [100, 200])
    end
    io = StringIO.new
    doc.write(io)

    post '/api/templates/pdf',
         params: { roles: %w[Customer], documents: [{ file_base64: Base64.strict_encode64(io.string) }],
                   fields: [{ name: 'sign', role: 'Customer', type: 'signature',
                              anchor: { text: '~cus-sign~', y_offset: -22, width: 150, height: 36 } }] }.to_json,
         headers: { 'x-auth-token': author.access_token.token, 'content-type': 'application/json' }

    expect(response).to have_http_status(:ok)
    areas = response.parsed_body['fields'].first['areas']
    expect(areas.pluck('page')).to eq([0, 1])
    # anchor sits 200pt up from the bottom of a 792pt page: 592pt from the top, less the 22pt offset
    expect(areas.first['x']).to be_within(0.005).of(100 / 612.0)
    expect(areas.first['y']).to be_within(0.01).of((792 - 200 - 2 - 22) / 792.0)
    expect(areas.first['w']).to be_within(0.001).of(150 / 612.0)
  end

  it 'rejects an anchor that is not in the document unless it is optional' do
    body = lambda do |optional|
      { roles: %w[A], documents: [{ file_base64: pdf }],
        fields: [{ name: 'x', role: 'A', type: 'text', anchor: { text: '~nope~', optional: } }] }.to_json
    end
    headers = { 'x-auth-token': author.access_token.token, 'content-type': 'application/json' }

    post('/api/templates/pdf', params: body.call(false), headers:)
    expect(response).to have_http_status(:unprocessable_content)

    post('/api/templates/pdf', params: body.call(true), headers:)
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body['fields'].first['areas']).to eq([])
  end
end
