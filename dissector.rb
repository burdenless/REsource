#!/usr/bin/ruby
#
# Tool for initial malware triage
# developed by: Pendrak0n
#

begin
  gem "bundler"
rescue LoadError
  system("gem install bundler")
  Gem.clear_paths
end

require 'rubygems'
require 'bundler/setup'
require 'trollop'
load 'scalpel.rb'

opts = Trollop::options do
  opt :file, "File to analyze", :type => :string
  opt :recurse, "Toggle recursive analysis on a folder", :default => false
end

if opts[:recurse] == true
  p "Dummy procedure until recursivity is built"
  exit
elsif opts[:file_given] == true
  file = opts[:file]
  analyze = Analysis.new
  type = analyze.identify(file)
else  
  help = Trollop::Parser.new
  help.parse(opts)
  help.educate
  exit
end

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
puts " Analysis complete!"
