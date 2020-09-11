# frozen_string_literal: true

module ShopifyApp
  module JwtAuthenticated
    extend ActiveSupport::Concern

    included do
      include ShopifyApp::Localization
      include ShopifyApp::CsrfProtection
      include ShopifyApp::EmbeddedApp
      before_action :login_again_if_different_user_or_shop
      around_action :activate_shopify_session
    end

    ACCESS_TOKEN_REQUIRED_HEADER = 'X-Shopify-API-Request-Failure-Unauthorized'

    def activate_shopify_session
      if user_expected? && user.blank?
        return signal_access_token_required
      end

      # TODO: Temporary until we have redirect-less Offline Access Token support
      return redirect_to_login if current_shopify_session.blank?

      begin
        ShopifyAPI::Base.activate_session(current_shopify_session)
        yield
      ensure
        ShopifyAPI::Base.clear_session
      end
    end

    def current_shopify_session
      @current_shopify_session ||=
        begin
          shopify_session || user || shop
        end
    end

    def shopify_session
      # TODO: Configure a "true" Shopify session using the `sid` value from JWT
    end

    # TODO: What's a better name for this?
    def user
      return unless ShopifyApp.configuration.allow_jwt_authentication
      return unless jwt_shopify_user_id
      ShopifyApp::SessionRepository.retrieve_user_session_by_shopify_user_id(jwt_shopify_user_id)
    end

    # TODO: What's a better name for this?
    def shop
      return unless ShopifyApp.configuration.allow_jwt_authentication
      return unless jwt_shopify_domain
      ShopifyApp::SessionRepository.retrieve_shop_session_by_shopify_domain(jwt_shopify_domain)
    end

    def signal_access_token_required
      response.set_header(ACCESS_TOKEN_REQUIRED_HEADER, true)
    end

    private

    def redirect_to_login
      if request.xhr?
        head(:unauthorized)
      else
        if request.get?
          path = request.path
          query = sanitized_params.to_query
        else
          referer = URI(request.referer || "/")
          path = referer.path
          query = "#{referer.query}&#{sanitized_params.to_query}"
        end
        session[:return_to] = query.blank? ? path.to_s : "#{path}?#{query}"
        redirect_to(login_url_with_optional_shop)
      end
    end

    def login_again_if_different_user_or_shop
      if session[:user_session].present? && params[:session].present?
        clear_session = session[:user_session] != params[:session]
      end

      if current_shopify_session &&
        params[:shop] && params[:shop].is_a?(String) &&
        (current_shopify_session.domain != params[:shop])
        clear_session = true
      end

      if clear_session
        clear_shopify_session
        redirect_to_login
      end
    end

    def jwt_shopify_user_id
      request.env['jwt.shopify_user_id']
    end

    def jwt_shopify_domain
      request.env['jwt.shopify_domain']
    end

    def user_expected?
      !ShopifyApp.configuration.user_session_repository.blank? && ShopifyApp::SessionRepository.user_storage.present?
    end
  end
end
