#!/usr/bin/env ruby
require 'cbor-pure'
require 'treetop'
require 'cbor-diag-parser'
require 'cbor-diagnostic'
require 'cbor-pretty'

options = ''
while /\A-([etu]+)\z/ === ARGV[0]
  options << $1
  ARGV.shift
end

ARGF.binmode
i = ARGF.read
while !i.empty?
  o, i = CBOR.decode_with_rest(i)
  puts CBOR::pretty(CBOR::encode(o))
  if !i.empty?
    print "\n,\n"
  end
end
