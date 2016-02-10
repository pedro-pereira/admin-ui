require 'logger'
require 'openssl'
require 'thin'
require 'thread'
require_relative 'admin/config'
require_relative 'admin/cc'
require_relative 'admin/cc_rest_client'
require_relative 'admin/db/dbstore_migration'
require_relative 'admin/doppler'
require_relative 'admin/email'
require_relative 'admin/event_machine_loop'
require_relative 'admin/login'
require_relative 'admin/log_files'
require_relative 'admin/logger'
require_relative 'admin/nats'
require_relative 'admin/operation'
require_relative 'admin/secure_web'
require_relative 'admin/stats'
require_relative 'admin/varz'
require_relative 'admin/view_models'
require_relative 'admin/web'

module AdminUI
  class Admin
    def initialize(config_hash, testing, start_callback = nil)
      @config_hash    = config_hash
      @testing        = testing
      @start_callback = start_callback

      @running = true
    end

    def start
      setup_traps
      setup_config
      setup_logger
      setup_dbstore
      setup_event_machine_loop
      setup_components

      display_files

      launch_web
    end

    def shutdown
      return unless @running

      @running = false

      @view_models.shutdown
      @stats.shutdown
      @varz.shutdown
      @nats.shutdown
      @doppler.shutdown
      @cc.shutdown
      @event_machine_loop.shutdown

      @view_models.join
      @stats.join
      @varz.join
      @nats.join
      @doppler.join
      @cc.join
      @event_machine_loop.join
    end

    private

    def setup_traps
      %w(TERM INT).each do |signal|
        trap(signal) do
          puts "\n\n"
          puts 'Shutting down ...'

          # Synchronize cannot be called from a trap context in ruby 2.x
          thread = Thread.new do
            shutdown
          end
          thread.join

          puts 'Exiting'
          puts "\n"
          exit!
        end
      end
    end

    def setup_config
      @config = Config.load(@config_hash)
    end

    def setup_logger
      @logger = AdminUILogger.new(@config.log_file, Logger::DEBUG)
    end

    def setup_dbstore
      connection = DBStoreMigration.new(@config, @logger, @testing)
      connection.migrate_to_db
    end

    def setup_event_machine_loop
      @event_machine_loop = EventMachineLoop.new(@config, @logger, @testing)
    end

    def setup_components
      email = EMail.new(@config, @logger)

      @client      = CCRestClient.new(@config, @logger)
      @cc          = CC.new(@config, @logger, @testing)
      @doppler     = Doppler.new(@config, @logger, @client, email, @testing)
      @log_files   = LogFiles.new(@config, @logger)
      @login       = Login.new(@config, @logger, @client)
      @nats        = NATS.new(@config, @logger, email, @testing)
      @varz        = VARZ.new(@config, @logger, @nats, @testing)
      @stats       = Stats.new(@config, @logger, @cc, @doppler, @varz, @testing)
      @view_models = ViewModels.new(@config, @logger, @cc, @doppler, @log_files, @stats, @varz, @testing)
      @operation   = Operation.new(@config, @logger, @cc, @client, @doppler, @varz, @view_models)
    end

    def display_files
      return if @testing
      puts "\n\n"
      puts 'AdminUI...'

      begin
        puts "  #{RUBY_ENGINE}           #{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}"
        @logger.info("#{RUBY_ENGINE} #{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}")
      rescue => error
        @logger.error("Unable to display RUBY_ENGINE, RUBY_VERSION or RUBY_PATCHLEVEL: #{error.inspect}")
      end

      puts "  data:          #{@config.data_file}"
      puts "  doppler data:  #{@config.doppler_data_file}"
      puts "  log:           #{@config.log_file}"
      puts "  stats:         #{@config.db_uri}"
      puts "\n"
    end

    def launch_web
      # Only show error and fatal messages
      Thin::Logging.level = Logger::ERROR

      web_hash =
        {
          Host:    @config.bind_address,
          Port:    @config.port,
          signals: false
        }

      web_hash[:StartCallback] = @start_callback if @start_callback

      ssl         = false
      ssl_options = {}

      if @config.secured_client_connection
        ssl   = true
        pkey  = OpenSSL::PKey::RSA.new(File.open(@config.ssl_private_key_file_path).read, @config.ssl_private_key_pass_phrase)
        cert  = OpenSSL::X509::Certificate.new(File.open(@config.ssl_certificate_file_path).read)

        ssl_options[:cert_chain_file]  = cert
        ssl_options[:private_key_file] = pkey
        ssl_options[:verify_peer]      = false

        web_class = AdminUI::SecureWeb
      else
        web_class = AdminUI::Web
      end

      web = web_class.new(@config,
                          @logger,
                          @cc,
                          @client,
                          @doppler,
                          @login,
                          @log_files,
                          @operation,
                          @stats,
                          @varz,
                          @view_models)

      Rack::Handler::Thin.run(web, web_hash) do |server|
        server.ssl         = ssl
        server.ssl_options = ssl_options
      end

      @start_callback.call if @start_callback

      sleep_amount = @testing ? 0.1 : 1
      sleep(sleep_amount) while @running
      puts "after sleeps"
    end
  end
end
