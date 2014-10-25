module OmniAuth
  module Strategies
    class Email
      include OmniAuth::Strategy

      option :signin, -> (email, token) { raise "you need to handle the signin with email #{email} and token #{token}" }

      def request_phase
        email_form
      end

      def other_phase
        if on_email_path?
          if request.post?
            handle_signin
          end
        else
          call_app!
        end
      end

      def handle_signin
        if email = request.params['email']
          token = SecureRandom.uuid
          session[:omniauth_email] = {
            'email' => email,
            'token' => token,
          }
          options[:signin].call(email, token)
        end
        email_form(email)
      end

      def email_form(email = nil)
        OmniAuth::Form.build(url: email_path) { |f|
          f.html "<p>An e-mail for login was sent to #{email}.</p>" if email
          f.text_field 'E-mail', 'email'
        }.to_response
      end

      def callback_phase
        if session[:omniauth_email].present? && request['token'] != session[:omniauth_email]['token']
          fail!(:invalid_credentials)
        else
          super
        end
      end

      def email_path
        options[:email_path] || "#{path_prefix}/#{name}/email"
      end

      def on_email_path?
        on_path?(email_path)
      end

      uid do
        Digest::SHA256.new.hexdigest(session[:omniauth_email]['email'])
      end

      info do
        {email: session[:omniauth_email]['email']}.with_indifferent_access
      end
    end
  end
end
