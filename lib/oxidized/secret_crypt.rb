# frozen_string_literal: true

require 'openssl'
require 'json'
require 'base64'

module Oxidized
  # Encrypts secret values found in device configs instead of removing them, so a backup keeps
  # the secret (recoverable) without exposing it in clear in the version-control output.
  #
  # Enabled by the `encrypt_secret` var (a hash); models opt in by passing captured secrets to
  # Model#hide, which calls here when `encrypt_secret` is set (and falls back to redaction
  # otherwise). See docs/Configuration.md.
  #
  #   vars:
  #     encrypt_secret:
  #       command: "age -R /etc/oxidized/recipients.txt"   # secret on stdin -> ciphertext on stdout
  #       fingerprint_key_file: "/etc/oxidized/secret-fp.key"  # HMAC key: stable token per secret
  #       cache_file: "/etc/oxidized/secret-cache.json"        # {fingerprint => token}
  #
  # Design (no application key escrow):
  #   - `command` is any tool that reads a secret on stdin and writes ciphertext on stdout
  #     (e.g. `age -R recipients`, `gpg -e -r KEYID --batch`). Oxidized never decrypts; only a
  #     holder of the corresponding private key can. No crypto dependency is added to oxidized.
  #   - the optional keyed fingerprint detects change: an unchanged secret reuses its existing
  #     token, so a non-deterministic backend (age/gpg) does not churn a new commit every run.
  #
  # Token: ENC[v1:<fingerprint>:<base64 ciphertext>]  (the fingerprint is omitted if no key).
  #
  # Fail-safe: any misconfiguration or command failure REDACTS the value (it is never written
  # back in clear).
  module SecretCrypt
    REDACTED = '<secret hidden>'

    @mutex  = Mutex.new
    @caches = {}
    @keys   = {}

    class << self
      # value -> ENC[...] token (or REDACTED on failure). `cfg` is the `encrypt_secret` hash.
      def enc(value, cfg)
        return value if value.nil? || value.empty?
        return value if value.start_with?('ENC[')   # idempotent: never re-encrypt a token

        cfg = stringify(cfg)
        command = cfg['command']
        return REDACTED if command.nil? || command.empty?

        @mutex.synchronize do
          fp    = fingerprint(value, cfg)
          store = cache(cfg)
          token = fp && store[fp]
          unless token
            ciphertext = run(command, value)
            return REDACTED if ciphertext.nil? || ciphertext.empty?

            b64   = Base64.strict_encode64(ciphertext)
            token = fp ? "ENC[v1:#{fp}:#{b64}]" : "ENC[v1:#{b64}]"
            if fp
              store[fp] = token   # cache the FULL token, read back verbatim (no re-wrap)
              persist(cfg, store)
            end
          end
          token
        end
      rescue StandardError => e
        Oxidized.logger.error "encrypt_secret failed: #{e.message}" if defined?(Oxidized.logger)
        REDACTED
      end

      private

      # Accept a Hash or an oxidized config object. Asetus::ConfigStruct defines #each (yielding
      # [k, v]) but not Enumerable, and its method_missing swallows each_with_object/to_h — so
      # build the hash with #each explicitly.
      def stringify(cfg)
        return {} unless cfg.respond_to?(:each)

        h = {}
        cfg.each { |k, v| h[k.to_s] = v }
        h
      end

      # HMAC(key, value) so the cache key / token marker does not reveal a crackable hash of the
      # secret. Returns nil (no fingerprint) when no key is configured.
      def fingerprint(value, cfg)
        path = cfg['fingerprint_key_file']
        return nil if path.nil? || path.empty?

        key = (@keys[path] ||= File.binread(path).strip)
        return nil if key.empty?

        OpenSSL::HMAC.hexdigest('SHA256', key, value)[0, 16]
      end

      def cache(cfg)
        path = cfg['cache_file']
        return {} if path.nil? || path.empty?

        @caches[path] ||= (File.exist?(path) ? JSON.parse(File.read(path)) : {})
      end

      def persist(cfg, store)
        path = cfg['cache_file']
        return if path.nil? || path.empty?

        tmp = "#{path}.#{Process.pid}.tmp"
        File.write(tmp, JSON.generate(store))
        File.rename(tmp, path)
      rescue StandardError
        # a non-persisted cache only costs a re-encrypt next run; never fatal
      end

      # Pipe the secret to the configured command's stdin; read ciphertext from stdout.
      def run(command, value)
        output = nil
        IO.popen(command, 'r+b') do |io|
          io.write(value)
          io.close_write
          output = io.read
        end
        $?&.success? ? output : nil
      end
    end
  end
end
