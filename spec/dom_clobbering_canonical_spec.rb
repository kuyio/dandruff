# frozen_string_literal: true

require 'rspec'
require 'dandruff'

RSpec.describe 'DOM clobbering canonical denylist' do
  it 'includes the canonical identifier list' do
    canonical = %w[
      __proto__ __parent__ constructor prototype contentwindow contentdocument parentnode ownerdocument location
      attributes nodevalue innerhtml outerhtml localname documenturi srcdoc url
      createelement renamenode appendchild insertbefore replacechild removechild normalize clonenode
    ]
    actual = Dandruff::Attributes::DOM_CLOBBERING.map(&:downcase)
    expect(actual).to include(*canonical)
  end
end
