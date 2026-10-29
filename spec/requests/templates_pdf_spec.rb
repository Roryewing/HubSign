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
         params: { roles: %w[A], documents: [{ file_base64: pdf }], fields: [{ name: 'x', role: 'B', type: 'text' }] }.to_json,
         headers: { 'x-auth-token': author.access_token.token, 'content-type': 'application/json' }

    expect(response).to have_http_status(:unprocessable_content)
  end
end
