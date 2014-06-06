#!/usr/bin/ruby
#
# Tool for initial malware triage
# developed by: Pendrak0n
#
###

begin
  gem "bundler"
rescue LoadError
  system("gem install bundler")
  Gem.clear_paths
end

require 'rubygems'
require 'bundler/setup'
load 'scalpel.rb'

print '[?]'.yellow
puts ' File to analyze:'
print '> '.yellow
file = gets.chomp

analyze = Analysis.new
type = analyze.identify(file)

banner = "\n========== Analyzing #{type} =========="
puts banner.yellow

case type
  when "PE"
    analyze.scan_pe(file)
  when "JPG"
    analyze.scan_jpg(file)
  when "ELF"
    analyze.scan_elf(file)
  when "Script"
    analyze.scan_script(file)
  else
    puts "[!] Analysis cannot complete. Filetype unknown.".red
end

print "\n[+]".green
puts "Analysis complete!"