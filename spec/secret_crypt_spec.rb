require_relative 'spec_helper'
require 'oxidized/secret_crypt'
require 'tmpdir'

describe Oxidized::SecretCrypt do
  # `base64` is a stand-in for a real backend (age/gpg): reads stdin, writes transformed bytes.
  def cfg(dir, command: 'base64', fp: true, cache: true)
    c = { 'command' => command }
    c['fingerprint_key_file'] = File.join(dir, 'fp.key') if fp
    c['cache_file'] = File.join(dir, 'cache.json') if cache
    c
  end

  before do
    # the module memoizes caches/keys per path; isolate each test in its own tmpdir
    Oxidized::SecretCrypt.instance_variable_set(:@caches, {})
    Oxidized::SecretCrypt.instance_variable_set(:@keys, {})
  end

  it 'passes through empty/nil values untouched' do
    _(Oxidized::SecretCrypt.enc('', { 'command' => 'base64' })).must_equal ''
    _(Oxidized::SecretCrypt.enc(nil, { 'command' => 'base64' })).must_be_nil
  end

  it 'redacts (never leaks) when no command is configured' do
    _(Oxidized::SecretCrypt.enc('s3cret', {})).must_equal '<secret hidden>'
  end

  it 'redacts when the backend command fails' do
    Dir.mktmpdir do |dir|
      _(Oxidized::SecretCrypt.enc('s3cret', cfg(dir, command: 'false'))).must_equal '<secret hidden>'
    end
  end

  it 'produces an ENC[v1:fingerprint:ciphertext] token' do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'fp.key'), 'unit-test-key')
      token = Oxidized::SecretCrypt.enc('Sup3rS3cret', cfg(dir))
      _(token).must_match(/\AENC\[v1:[0-9a-f]{16}:[A-Za-z0-9+\/=]+\]\z/)
    end
  end

  it 'is stable: an unchanged secret yields the same token (no spurious diff)' do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'fp.key'), 'unit-test-key')
      a = Oxidized::SecretCrypt.enc('Sup3rS3cret', cfg(dir))
      b = Oxidized::SecretCrypt.enc('Sup3rS3cret', cfg(dir))
      _(a).must_equal b
    end
  end

  it 'gives different tokens for different secrets' do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'fp.key'), 'unit-test-key')
      a = Oxidized::SecretCrypt.enc('one', cfg(dir))
      b = Oxidized::SecretCrypt.enc('two', cfg(dir))
      _(a).wont_equal b
    end
  end

  it 'persists the fingerprint -> token cache' do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'fp.key'), 'unit-test-key')
      Oxidized::SecretCrypt.enc('Sup3rS3cret', cfg(dir))
      cache = JSON.parse(File.read(File.join(dir, 'cache.json')))
      _(cache.size).must_equal 1
    end
  end

  it 'omits the fingerprint when no key is configured' do
    Dir.mktmpdir do |dir|
      token = Oxidized::SecretCrypt.enc('Sup3rS3cret', cfg(dir, fp: false, cache: false))
      _(token).must_match(/\AENC\[v1:[A-Za-z0-9+\/=]+\]\z/)
    end
  end
end
