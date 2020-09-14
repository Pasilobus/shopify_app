# frozen_string_literal: true

require 'test_helper'

class JwtAuthenticatedTest < ActionController::TestCase
  class AuthenticatedTestController < ActionController::Base
    include ShopifyApp::JwtAuthenticated

    helper_method :current_shopify_session

    def index
      render(plain: "OK")
    end
  end

  tests AuthenticatedTestController

  setup do
    ShopifyApp::SessionRepository.shop_storage = ShopifyApp::InMemoryShopSessionStore
    ShopifyApp::SessionRepository.user_storage = ShopifyApp::InMemoryUserSessionStore

    ShopifyApp.configuration.allow_jwt_authentication = true
    ShopifyApp.configuration.api_key = 'api_key'

    request.env['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) '\
                                     'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'
  end

  test "includes all the needed concerns" do
    assert AuthenticatedTestController.include?(ShopifyApp::Localization)
    refute AuthenticatedTestController.include?(ShopifyApp::LoginProtection)
    assert AuthenticatedTestController.include?(ShopifyApp::CsrfProtection)
    assert AuthenticatedTestController.include?(ShopifyApp::EmbeddedApp)
  end

  test "#current_shopify_session retrieves user session when using jwt" do
    domain = 'https://test.myshopify.io'
    token = 'admin_api_token'
    dest = 'shopify_domain'
    sub = 'shopify_user'

    expected_session = ShopifyAPI::Session.new(
      domain: domain,
      token: token,
      api_version: '2020-01',
    )

    ShopifyApp::SessionRepository.expects(:retrieve_user_session_by_shopify_user_id)
      .at_most(2).with(sub).returns(expected_session)
    ShopifyApp::SessionRepository.expects(:retrieve_user_session).never
    ShopifyApp::SessionRepository.expects(:retrieve_shop_session_by_shopify_domain).never
    ShopifyApp::SessionRepository.expects(:retrieve_shop_session).never

    with_application_test_routes do
      request.env['jwt.shopify_domain'] = dest
      request.env['jwt.shopify_user_id'] = sub
      get :index

      assert_equal expected_session, @controller.current_shopify_session
    end
  end

  private

  def with_application_test_routes
    with_routing do |set|
      set.draw do
        get '/' => 'jwt_authenticated_test/authenticated_test#index'
      end
      yield
    end
  end
end
